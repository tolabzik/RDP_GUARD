import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import threading
import time

from .auth import Dispatcher
from .firewall import FirewallEngine
from .guard import Guard
from .proxy_client import ProxyWorker
from .storage import Store
from . import recovery


def configure_logging(directory: Path, name: str):
    directory.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(directory / f"{name}.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)


def run_guard(stop: threading.Event):
    from .windows.collector import Collector, QUERIES
    from .windows.firewall import WindowsFirewall
    from .windows.ipc import PipeServer
    from .windows.platform import DATA_DIR, WindowsSafety, firewall_mutex
    configure_logging(DATA_DIR / "logs", "guard")
    store = Store(DATA_DIR / "guard.db")
    guard = Guard(store, WindowsFirewall(), WindowsSafety(), DATA_DIR, firewall_lock=firewall_mutex)
    from .windows.recovery import TimeSynchronizer
    time_sync = TimeSynchronizer(DATA_DIR, stop)
    guard.safety.time_sync = time_sync
    (DATA_DIR / "guard.alive").touch()
    dispatcher = Dispatcher(guard)
    server = PipeServer(dispatcher, stop)
    collectors = [Collector(guard, channel, stop) for channel in QUERIES]
    proxy_worker = ProxyWorker(guard, stop)
    try:
        server.start()
        server.ready.wait(15)
        if not server.is_alive() or server.error:
            raise RuntimeError(server.error or "IPC server did not start")
        for collector in collectors:
            collector.start()
        proxy_worker.start()
        time_sync.start()
        while not stop.is_set():
            try:
                guard.tick()
            except Exception:
                logging.exception("Guard safety tick failed; active protection inhibited")
            (DATA_DIR / "guard.alive").touch()
            if not server.is_alive():
                raise RuntimeError("Guard IPC thread stopped; restarting service")
            stop.wait(1)
    finally:
        stop.set()
        with guard.lock:
            guard.stopping = True
        for collector in collectors:
            if collector.is_alive():
                collector.join(10)
        if proxy_worker.is_alive():
            proxy_worker.join(15)
        if time_sync.is_alive():
            time_sync.join(1)
        enrollment = getattr(guard, "proxy_enrollment", None)
        if enrollment is not None:
            enrollment.close()
        server.join(15)
        store.close()


def emergency_disable(reason="Local administrator"):
    from .windows.firewall import WindowsFirewall
    from .windows.platform import DATA_DIR, firewall_mutex, require_admin
    require_admin()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # Independent of SQLite, the main service, credentials, and the web panel.
    with firewall_mutex():
        (DATA_DIR / "emergency.disabled").write_text(reason, encoding="utf-8")
        recovery.revoke(DATA_DIR)
        FirewallEngine(WindowsFirewall()).clear()
        (DATA_DIR / "active-lease.json").unlink(missing_ok=True)
    recovery.ServiceJournal(DATA_DIR).transition("protection", "disabled", reason)
    configure_logging(DATA_DIR / "logs", "emergency")
    logging.warning("Emergency disable completed: %s", reason)
    return {"ok": True, "emergency_disabled": True, "managed_rules_removed": True}


def watchdog():
    from .windows.platform import DATA_DIR, require_admin, firewall_mutex
    require_admin()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "watchdog.alive").touch()
    if recovery.maintenance(DATA_DIR):
        return {"ok": True, "maintenance": True}
    try:
        # Serialize the read and withdrawal with Guard's lease renewal.
        with firewall_mutex():
            return _check_lease(DATA_DIR)
    finally:
        # Start recovery only after withdrawing old authority. The supervisor
        # must not prevent emergency cleanup even if SCM or its journal fail.
        from .windows.recovery import supervise_services
        try:
            supervise_services(DATA_DIR)
        except Exception:
            logging.exception("Service supervision failed; will retry next watchdog run")


def _check_lease(DATA_DIR):
    lease_path = DATA_DIR / "active-lease.json"
    if (DATA_DIR / "emergency.disabled").exists():
        return emergency_disable("Persistent emergency latch")
    if not lease_path.exists():
        return {"ok": True, "active_lease": False}
    try:
        lease = json.loads(lease_path.read_text(encoding="utf-8"))
        now = time.time()
        stale = now - lease["heartbeat"] > 45 or lease["heartbeat"] > now + 10
        expired = lease.get("deadline") is not None and now >= lease["deadline"]
        if stale or expired:
            if stale and not expired and lease.get("confirmed") is True and recovery.approval(DATA_DIR):
                # Clear only current authority. Keep durable, previously confirmed consent.
                from .windows.firewall import WindowsFirewall
                from .windows.platform import firewall_mutex
                with firewall_mutex():
                    FirewallEngine(WindowsFirewall()).clear()
                    lease_path.unlink(missing_ok=True)
                recovery.ServiceJournal(DATA_DIR).transition("protection", "waiting",
                    "Heartbeat службы устарел; блокировки сняты до повторной проверки")
                return {"ok": True, "recovery_pending": True}
            return emergency_disable("Rollback deadline or guard heartbeat expired")
    except (ValueError, KeyError, OSError, TypeError, AttributeError):
        return emergency_disable("Active lease is unreadable")
    return {"ok": True, "active_lease": True}
