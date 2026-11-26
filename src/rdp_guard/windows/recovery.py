"""Native recovery helpers; never replace domain/NTP policy or bypass activation."""
import os
from pathlib import Path
import subprocess
import threading
import time

from ..recovery import ServiceJournal, atomic_document, maintenance


class TimeSynchronizer(threading.Thread):
    def __init__(self, data_dir, stop, *, runner=None):
        super().__init__(name="rdpguard-time-sync", daemon=True)
        self.stop = stop
        self.journal = ServiceJournal(data_dir)
        self.runner = runner or self._run_command
        self._state = {"ready": False, "reason": "Ожидание синхронизации Windows Time"}
        self._success = None
        self._wall = None

    @staticmethod
    def _run_command(arguments):
        executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "w32tm.exe"
        result = subprocess.run([str(executable), *arguments], capture_output=True, timeout=25)
        text = (result.stdout + result.stderr).decode("oem", errors="replace").strip()
        if result.returncode:
            raise RuntimeError(f"Windows Time ({result.returncode}): {text[:800]}")
        return text

    def snapshot(self):
        valid = (self._success is not None and time.monotonic() - self._success < 900
                 and abs((time.time() - self._wall) - (time.monotonic() - self._success)) < 2)
        return self._state | {"ready": bool(valid and self._state["ready"])}

    def synchronize(self):
        self.runner(["/resync", "/rediscover"])
        source = self.runner(["/query", "/source"])
        # W32Time may report success while using its local oscillator.
        if not source or any(word in source.casefold() for word in ("cmos", "free-running", "свободно")):
            raise RuntimeError("Windows Time не подтвердил внешний источник времени: " + source)
        self._success, self._wall = time.monotonic(), time.time()
        self._state = {"ready": True, "reason": "Синхронизация выполнена", "source": source[:200],
                       "last_sync": self._wall}
        self.journal.transition("time", "synchronized", source[:200])

    def run(self):
        import win32serviceutil
        while not self.stop.is_set():
            try:
                if win32serviceutil.QueryServiceStatus("W32Time")[1] == 1:
                    win32serviceutil.StartService("W32Time")
                self.synchronize()
                delay = 300
            except Exception as exc:
                self._state = {"ready": False, "reason": str(exc)[:1000]}
                self.journal.transition("time", "retrying", str(exc))
                delay = 30
            self.stop.wait(delay)


def supervise_services(data_dir):
    """Run from SYSTEM watchdog, independently of Guard IPC/SQLite availability."""
    import win32serviceutil
    data_dir = Path(data_dir)
    if maintenance(data_dir):
        return
    journal = ServiceJournal(data_dir)
    public = {"checked_at": time.time(), "services": {}}
    for name in ("RDPGuardService", "RDPGuardWeb"):
        try:
            status = win32serviceutil.QueryServiceStatus(name)
            state, exit_code, service_code = status[1], status[3], status[4]
            public["services"][name] = {"state": state, "exit_code": exit_code,
                                         "service_exit_code": service_code}
            journal.transition(name + ":SCM", str(state),
                               f"SCM state={state}; Win32ExitCode={exit_code}; ServiceExitCode={service_code}")
            if state == 1:
                journal.record(name, "restart-requested",
                               "Служба остановлена. SCM не сообщает инициатора; запрошен повторный запуск.")
                win32serviceutil.StartService(name)
            elif name == "RDPGuardService" and state == 4:
                alive = data_dir / "guard.alive"
                # A newly started process gets time to initialise and subscribe.
                if alive.exists() and time.time() - alive.stat().st_mtime > 120:
                    journal.record(name, "unresponsive", "Нет отметки рабочего цикла более 120 секунд; запрошен перезапуск")
                    win32serviceutil.StopService(name)
        except Exception as exc:
            journal.transition(name + ":recovery", "failed", str(exc))
            public["services"][name] = {"state": "unavailable"}
    # This directory is the ONLY diagnostic state readable by the web identity.
    # It contains no credentials, addresses, user names, or exception details.
    status_dir = data_dir / "service-status"
    if status_dir.is_dir():
        atomic_document(status_dir / "status.json", public)


def scm_events(limit=40):
    """Return native SCM evidence without inventing an initiator for a stop."""
    import win32evtlog
    handle = win32evtlog.OpenEventLog(None, "System")
    rows = []
    names = ("RDPGuardService", "RDPGuardWeb", "RDP Guard Protection Service", "RDP Guard Local Web Panel")
    try:
        scanned = 0
        while len(rows) < limit and scanned < 1500:
            batch = win32evtlog.ReadEventLog(handle, win32evtlog.EVENTLOG_BACKWARDS_READ |
                                           win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            if not batch:
                break
            for event in batch:
                scanned += 1
                values = event.StringInserts or []
                if event.SourceName == "Service Control Manager" and any(name in values for name in names):
                    rows.append({"timestamp": event.TimeGenerated.timestamp(), "component": "Windows SCM",
                                 "event": str(event.EventID & 0xFFFF), "detail": " · ".join(values)[:2000]})
                    if len(rows) >= limit:
                        break
        return rows
    finally:
        win32evtlog.CloseEventLog(handle)
