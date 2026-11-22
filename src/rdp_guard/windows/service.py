import logging
import sys
import threading

import servicemanager
import win32service
import win32serviceutil


class BaseService(win32serviceutil.ServiceFramework):
    def __init__(self, args):
        super().__init__(args)
        self.stop = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=30000)
        self.stop.set()

    def SvcShutdown(self):
        self.SvcStop()

    def SvcDoRun(self):
        try:
            self.work()
        except Exception:
            logging.exception("Service terminated")
            servicemanager.LogErrorMsg(f"{self._svc_name_}: startup/runtime failed; inspect protected logs")
            # SCM failure recovery is deliberately limited to two restarts by the installer.
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
