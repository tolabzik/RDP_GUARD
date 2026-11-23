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
        while not stop.is_set():
            try:
                guard.tick()
            except Exception:
                logging.exception("Guard safety tick failed; active protection inhibited")
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
    (DATA_DIR / "emergency.disabled").write_text(reason, encoding="utf-8")
    with firewall_mutex():
        FirewallEngine(WindowsFirewall()).clear()
    (DATA_DIR / "active-lease.json").unlink(missing_ok=True)
    configure_logging(DATA_DIR / "logs", "emergency")
    logging.warning("Emergency disable completed: %s", reason)
    return {"ok": True, "emergency_disabled": True, "managed_rules_removed": True}


def watchdog():
    from .windows.platform import DATA_DIR, require_admin
    require_admin()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "watchdog.alive").touch()
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
            return emergency_disable("Rollback deadline or guard heartbeat expired")
    except (ValueError, KeyError, OSError):
        return emergency_disable("Active lease is unreadable")
    return {"ok": True, "active_lease": True}
