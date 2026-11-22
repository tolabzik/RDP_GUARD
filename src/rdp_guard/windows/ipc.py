from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import json
import logging
import threading
import time

from ..auth import AuthenticationError, RateLimitError
from .platform import PIPE_NAME

MAX_REQUEST = 262144
MAX_RESPONSE = 8388608
LOG = logging.getLogger(__name__)


def security_attributes():
    import pywintypes
    import win32security
    web_sid = win32security.LookupAccountName(None, r"NT SERVICE\RDPGuardWeb")[0]
    sid = win32security.ConvertSidToStringSid(web_sid)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    # The web SID can read/write data, but cannot create additional server instances (bit 0x4).
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;{sid})", 1)
    return attributes, sid


def peer_identity(handle, web_sid):
    import win32api
    import win32security
    win32security.ImpersonateNamedPipeClient(handle)
    try:
        token = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32security.TOKEN_QUERY, True)
        try:
            sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
            groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
            enabled = {win32security.ConvertSidToStringSid(s) for s, attributes in groups if attributes & 4 and not attributes & 16}
            if web_sid in enabled or sid == web_sid:
                return {"role": "web", "sid": sid}
            if sid == "S-1-5-18" or "S-1-5-32-544" in enabled:
                return {"role": "admin", "sid": sid}
            raise AuthenticationError("Named pipe client is not authorized")
        finally:
            token.Close()
    finally:
        win32security.RevertToSelf()


def _overlapped(handle, start, timeout=10000, stop=None):
    import pywintypes
    import win32event
    import win32file
    ov = pywintypes.OVERLAPPED()
    ov.hEvent = win32event.CreateEvent(None, True, False, None)
    try:
        try:
            result = start(ov)
            # pywin32 returns ERROR_PIPE_CONNECTED (it does not raise it). No I/O
            # was queued in this race, so the OVERLAPPED event will never signal.
            if result == 535:
                return 0
        except pywintypes.error as exc:
            if exc.winerror == 535:  # Client connected between CreateNamedPipe and ConnectNamedPipe.
                return 0
            if exc.winerror != 997:
                raise
        elapsed = 0
        while win32event.WaitForSingleObject(ov.hEvent, 250) != win32event.WAIT_OBJECT_0:
            elapsed += 250
            if elapsed >= timeout or (stop and stop.is_set()):
                # This same thread issued the sole outstanding operation on this handle.
                # pywin32 exposes CancelIo; it does not expose CancelIoEx in supported builds.
                win32file.CancelIo(handle)
                try:
                    win32file.GetOverlappedResult(handle, ov, True)
                except pywintypes.error:
                    pass
                raise TimeoutError("Named pipe operation timed out")
        return win32file.GetOverlappedResult(handle, ov, False)
    finally:
        ov.hEvent.Close()


def read_message(handle, limit):
    import win32file
    buffer = win32file.AllocateReadBuffer(limit)
    count = _overlapped(handle, lambda ov: win32file.ReadFile(handle, buffer, ov))
    if not 0 < count <= limit:
        raise ValueError("Invalid pipe message size")
    return json.loads(bytes(buffer[:count]).decode("utf-8"))


def write_message(handle, value, limit):
    import win32file
    payload = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(payload) > limit:
        raise ValueError("Pipe message is too large")
    count = _overlapped(handle, lambda ov: win32file.WriteFile(handle, payload, ov))
    if count != len(payload):
        raise RuntimeError("Incomplete pipe write")


def verify_server(handle):
    import os
    from pathlib import Path
    import win32service
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    kernel.GetNamedPipeServerProcessId.restype = wintypes.BOOL
    pid = wintypes.ULONG()
    if not kernel.GetNamedPipeServerProcessId(int(handle), ctypes.byref(pid)):
        raise ctypes.WinError(ctypes.get_last_error())
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        service = win32service.OpenService(manager, "RDPGuardService",
                                          win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_QUERY_CONFIG)
        try:
            status = win32service.QueryServiceStatusEx(service)
            config = win32service.QueryServiceConfig(service)
            expected = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RDPGuard" / "guardservice.exe"
            if (status["ProcessId"] != pid.value or Path(config[3].strip('"')) != expected or
                    config[7].lower() not in ("localsystem", "nt authority\\system")):
                raise AuthenticationError("Pipe server does not match the installed SYSTEM guard service")
        finally:
            win32service.CloseServiceHandle(service)
    finally:
        win32service.CloseServiceHandle(manager)


def _connect(timeout=5000):
    import pywintypes
    import win32con
    import win32file
    import win32pipe
    deadline = time.monotonic() + timeout / 1000
    while True:
        try:
            # FILE_WRITE_ATTRIBUTES selects message-read mode. Omit FILE_CREATE_PIPE_INSTANCE,
            # unlike GENERIC_WRITE, and retain identification-only impersonation protection.
            return win32file.CreateFile(PIPE_NAME, 0x12019B, 0, None, win32con.OPEN_EXISTING,
                                       win32con.FILE_FLAG_OVERLAPPED | 0x00100000 | 0x00010000, None)
        except pywintypes.error as exc:
            if exc.winerror != 231:  # ERROR_PIPE_BUSY: another client claimed the available instance.
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Named pipe connection timed out") from exc
            try:
                win32pipe.WaitNamedPipe(PIPE_NAME, max(1, int(remaining * 1000)))
            except pywintypes.error as wait_error:
                if wait_error.winerror == 121:
                    raise TimeoutError("Named pipe connection timed out") from wait_error
                raise
            # WaitNamedPipe does not reserve the instance. Retry only opening the handle;
            # once a request is sent it must never be replayed, especially a mutation.


class PipeClient:
    def call(self, request):
        import win32pipe
        handle = _connect()
        try:
            verify_server(handle)
            win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
            write_message(handle, request, MAX_REQUEST)
            response = read_message(handle, MAX_RESPONSE)
            write_message(handle, {"ack": True}, 1024)
            if not response.get("ok"):
                raise RemoteError(response.get("error", "Service request failed"), response.get("code", 503))
            return response["result"]
        finally:
            handle.Close()


class RemoteError(RuntimeError):
    def __init__(self, message, code=503):
        super().__init__(message)
        self.code = code


class PipeServer(threading.Thread):
    def __init__(self, dispatcher, stop):
        super().__init__(name="named-pipe", daemon=True)
        self.dispatcher, self.stop = dispatcher, stop
        self.ready = threading.Event()
        self.error = None
        self.slots = threading.Semaphore(4)

    def run(self):
        import win32con
        import win32pipe
        attributes, web_sid = security_attributes()
        def create(first=False):
            return win32pipe.CreateNamedPipe(PIPE_NAME,
                win32pipe.PIPE_ACCESS_DUPLEX | win32con.FILE_FLAG_OVERLAPPED | (0x00080000 if first else 0),
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | 0x8, 5,
                65536, 65536, 5000, attributes)
        handle = None
        try:
            handle = create(True)
            self.ready.set()
            with ThreadPoolExecutor(max_workers=4, thread_name_prefix="rpc") as pool:
                while not self.stop.is_set():
                    if not self.slots.acquire(timeout=0.25):
                        continue
                    try:
                        _overlapped(handle, lambda ov: win32pipe.ConnectNamedPipe(handle, ov), timeout=86400000, stop=self.stop)
                    except TimeoutError:
                        self.slots.release()
                        if self.stop.is_set():
                            break
                        continue
                    connected = handle
                    # Keep a server instance alive at all times, preventing a pipe-name squatting gap.
                    handle = create()
                    pool.submit(self.serve, connected, web_sid)
        except Exception as exc:
            self.error = str(exc)
            LOG.exception("IPC server failed")
            self.stop.set()
        finally:
            self.ready.set()
            if handle:
                handle.Close()

    def serve(self, handle, web_sid):
        import win32pipe
        try:
            request = read_message(handle, MAX_REQUEST)
            identity = peer_identity(handle, web_sid)
            try:
                result = self.dispatcher(request, identity)
                response = {"ok": True, "result": result}
            except RateLimitError as exc:
                response = {"ok": False, "code": 429, "error": str(exc)}
            except AuthenticationError as exc:
                response = {"ok": False, "code": 401, "error": str(exc)}
            except (ValueError, KeyError) as exc:
                response = {"ok": False, "code": 400, "error": str(exc)}
            except Exception:
                LOG.exception("Guard request failed")
                response = {"ok": False, "code": 503, "error": "Guard operation failed; inspect System diagnostics"}
            write_message(handle, response, MAX_RESPONSE)
            # A bounded acknowledgement ensures DisconnectNamedPipe cannot discard an unread reply.
            if read_message(handle, 1024) != {"ack": True}:
                raise ValueError("Missing response acknowledgement")
        except Exception:
            LOG.warning("IPC connection failed", exc_info=True)
        finally:
            # No FlushFileBuffers: it can block indefinitely on a stalled peer.
            try:
                win32pipe.DisconnectNamedPipe(handle)
            finally:
                handle.Close()
                self.slots.release()
