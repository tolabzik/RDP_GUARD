import logging
import sys
import threading
import json

import servicemanager
import win32service
import win32serviceutil


class BaseService(win32serviceutil.ServiceFramework):
    def __init__(self, args):
        super().__init__(args)
        self.stop = threading.Event()
        self.stop_reason = ""

    def event(self, kind, detail=""):
        from ..recovery import ServiceJournal
        from .platform import DATA_DIR
        # Web runs unprivileged; its errors stay in its own log and Windows SCM.
        if self._svc_name_ == "RDPGuardService":
            ServiceJournal(DATA_DIR).record(self._svc_name_, kind, detail)

    def SvcStop(self):
        self.stop_reason = "Получена команда STOP от SCM; инициатор в этой команде не указан"
        self.event("stop-requested", self.stop_reason)
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=30000)
        self.stop.set()

    def SvcShutdown(self):
        self.stop_reason = "Windows завершает работу"
        self.event("shutdown", self.stop_reason)
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=30000)
        self.stop.set()

    def SvcDoRun(self):
        from .platform import DATA_DIR
        from ..recovery import atomic_document
        marker = DATA_DIR / "guard-process.json"
        try:
            if self._svc_name_ == "RDPGuardService":
                (DATA_DIR / "guard.alive").touch()
                try:
                    previous = json.loads(marker.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    previous = {}
                if isinstance(previous, dict) and previous.get("running"):
                    self.event("unclean-exit", "Предыдущий процесс не записал завершение. Причина неизвестна; проверьте события Windows SCM.")
                try:
                    atomic_document(marker, {"running": True})
                except OSError:
                    logging.exception("Cannot write lifecycle marker")
            self.event("started", "Служба запущена")
            self.work()
            if not self.stop.is_set():
                raise RuntimeError("Service worker returned without a stop request")
            self.event("stopped", self.stop_reason)
            if self._svc_name_ == "RDPGuardService":
                try:
                    atomic_document(marker, {"running": False})
                except OSError:
                    logging.exception("Cannot close lifecycle marker")
        except Exception as exc:
            self.event("failed", f"{type(exc).__name__}: {exc}")
            logging.exception("Service terminated")
            servicemanager.LogErrorMsg(f"{self._svc_name_}: startup/runtime failed; inspect protected logs")
            # SCM repeats its final delayed restart action; watchdog also observes stopped services.
            raise


class GuardService(BaseService):
    _svc_name_ = "RDPGuardService"
    _svc_display_name_ = "RDP Guard Protection Service"
    _svc_description_ = "Collects authentication events and manages scoped RDPGuard firewall rules."

    def work(self):
        from ..runtime import run_guard
        run_guard(self.stop)


class WebService(BaseService):
    _svc_name_ = "RDPGuardWeb"
    _svc_display_name_ = "RDP Guard Local Web Panel"
    _svc_description_ = "Unprivileged authenticated management panel on 127.0.0.1:8787."

    def work(self):
        from ..web.app import run_web
        run_web(self.stop)


def service_main(cls):
    if len(sys.argv) > 1:
        win32serviceutil.HandleCommandLine(cls)
    else:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(cls)
        servicemanager.StartServiceCtrlDispatcher()
