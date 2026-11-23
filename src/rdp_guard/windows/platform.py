from contextlib import contextmanager
import ctypes
import ipaddress
import os
from pathlib import Path
import socket
import sys
import time

from ..models import address

DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RDPGuard"
PIPE_NAME = r"\\.\pipe\RDPGuard.v1"
SESSION_RETRY_SECONDS = 2.0
SESSION_RETRY_INTERVAL = 0.1


def require_windows():
    if sys.platform != "win32":
        raise RuntimeError("This command requires Windows")


def require_admin():
    require_windows()
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError("Run this command from an elevated Administrator terminal")


def require_unprivileged():
    require_windows()
    import win32api
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    try:
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
        groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
        admin_member = any(win32security.ConvertSidToStringSid(s) == "S-1-5-32-544" for s, _ in groups)
        if sid == "S-1-5-18" or admin_member or ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError("The web process must not run as SYSTEM or an administrator")
    finally:
        token.Close()


@contextmanager
def com():
    import pythoncom
    pythoncom.CoInitialize()
    try:
        yield
    finally:
        pythoncom.CoUninitialize()


@contextmanager
def firewall_mutex():
    import win32api
    import win32event
    import win32security
    import pywintypes
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)", 1)
    handle = win32event.CreateMutex(attributes, False, r"Global\RDPGuard.Firewall.v1")
    acquired = False
    try:
        result = win32event.WaitForSingleObject(handle, 15000)
        if result not in (win32event.WAIT_OBJECT_0, win32event.WAIT_ABANDONED):
            raise TimeoutError("Firewall mutex timed out")
        acquired = True
        yield
    finally:
        if acquired:
            win32event.ReleaseMutex(handle)
        win32api.CloseHandle(handle)


class WindowsSafety:
    def __init__(self, monotonic=time.monotonic, sleep=time.sleep):
        from .sessions import SessionSourceResolver
        self._sources = SessionSourceResolver()
        self._monotonic, self._sleep = monotonic, sleep

    def sessions(self):
        # WTS can expose a new connection before its LSM record is readable.
        # Retry the whole inventory so a disconnect/reconnect during enumeration
        # also gets a fresh identity. Never reuse a failed or stale binding.
        deadline = self._monotonic() + SESSION_RETRY_SECONDS
        snapshot = self._sessions_once()
        while not snapshot["healthy"]:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                break
            self._sleep(min(SESSION_RETRY_INTERVAL, remaining))
            if self._monotonic() >= deadline:
                break
            snapshot = self._sessions_once()
        return snapshot

    def _sessions_once(self):
        import win32security
        import win32ts
        sessions = []
        try:
            for item in win32ts.WTSEnumerateSessions(None, 1, 0):
                if item["State"] != win32ts.WTSActive:
                    continue
                session_id = item["SessionId"]
                def query(field):
                    return win32ts.WTSQuerySessionInformation(None, session_id, field)
                if query(win32ts.WTSClientProtocolType) != 2:
                    continue
                started = self._sources.read_clock(session_id)
                token = win32ts.WTSQueryUserToken(session_id)
                try:
                    groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
                    user_sid = win32security.ConvertSidToStringSid(
                        win32security.GetTokenInformation(token, win32security.TokenUser)[0])
                    # Include deny-only admin groups: a UAC-filtered administrator still needs protection.
                    admin = any(win32security.ConvertSidToStringSid(sid) == "S-1-5-32-544" for sid, _ in groups)
                finally:
                    token.Close()
                if not admin:
                    continue
                username, domain = query(win32ts.WTSUserName), query(win32ts.WTSDomainName)
                try:
                    proof = self._sources.resolve(session_id, user_sid, username, domain, expected_clock=started)
                except Exception as exc:
                    raise RuntimeError(f"Session {session_id} ({domain}\\{username}): {exc}") from exc
                # Client-provided WTSClientAddress can be private/absent behind NAT or a gateway.
                # Keep it as diagnostics only; it never determines whitelist or firewall scope.
                reported = None
                try:
                    client = query(win32ts.WTSClientAddress)
                    if client:
                        family, raw = client["AddressFamily"], bytes(client["Address"])
                        if family == socket.AF_INET:
                            reported = address(socket.inet_ntop(socket.AF_INET, raw[2:6]))
                        elif family == socket.AF_INET6:
                            reported = address(socket.inet_ntop(socket.AF_INET6, raw[:16]))
                except Exception:
                    pass
                sessions.append({"id": session_id, "username": username, "domain": domain,
                                 "client_reported_ip": reported, **proof})
            return {"healthy": True, "sessions": sessions}
        except Exception as exc:
            return {"healthy": False, "sessions": sessions, "error": str(exc)}

    def health(self, port):
        import psutil
        import winreg
        import win32com.client
        result = {"firewall": False, "listening": False, "port_matches": False,
                  "allow_rules": False, "watchdog": False, "audit_logon": False, "errors": []}
        try:
            result["audit_logon"] = audit_logon_enabled()
            result["listening"] = any(c.status == "LISTEN" and c.laddr.port == port
                                      for c in psutil.net_connections(kind="tcp"))
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp") as key:
                result["port_matches"] = winreg.QueryValueEx(key, "PortNumber")[0] == port
        except Exception as exc:
            result["errors"].append(str(exc))
        try:
            with com():
                policy = win32com.client.Dispatch("HNetCfg.FwPolicy2")
                profiles = [p for p in (1, 2, 4) if policy.CurrentProfileTypes & p]
                result["firewall"] = bool(profiles) and all(policy.FirewallEnabled(p) and
                    not policy.BlockAllInboundTraffic(p) for p in profiles) and policy.LocalPolicyModifyState == 0
                active_sessions = self.sessions()
                if not active_sessions["healthy"]:
                    result["errors"].append(active_sessions.get("error", "Cannot verify administrative RDP sessions"))
                clients = [s["ip"] for s in active_sessions["sessions"]]
                covered = set()
                for rule in policy.Rules:
                    if not rule.Enabled or rule.Direction != 1 or rule.Action != 1 or rule.Protocol not in (6, 17):
                        continue
                    if rule.ServiceName and rule.ServiceName.lower() != "termservice":
                        continue
                    app = (rule.ApplicationName or "").lower().replace("%systemroot%", os.environ.get("SystemRoot", r"C:\Windows").lower())
                    if app and app != str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "svchost.exe").lower():
                        continue
                    if rule.LocalAddresses != "*" or rule.InterfaceTypes != "All" or rule.Interfaces:
                        continue
                    if not port_in_rule(rule.LocalPorts, port):
                        continue
                    if not clients or not all(remote_allowed(rule.RemoteAddresses, ip) for ip in clients):
                        continue
                    for profile in profiles:
                        if rule.Profiles & profile:
                            covered.add((profile, rule.Protocol))
                result["allow_rules"] = (active_sessions["healthy"] and bool(profiles) and
                    all((p, proto) in covered for p in profiles for proto in (6, 17)))
                rule = policy = None  # Release COM proxies before apartment uninitialization.
        except Exception as exc:
            result["errors"].append(str(exc))
        try:
            with com():
                scheduler = win32com.client.Dispatch("Schedule.Service")
                scheduler.Connect()
                task = scheduler.GetFolder("\\").GetTask("RDPGuardRollback")
                expected = str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RDPGuard" / "rdpguard.exe")
                checks = watchdog_checks(task, expected, self._watchdog_age())
                result["watchdog"] = all(checks.values())
                result["errors"].extend(f"Watchdog check failed: {name}" for name, ok in checks.items() if not ok)
                task = scheduler = None
        except Exception as exc:
            result["errors"].append(str(exc))
        return result

    @staticmethod
    def _watchdog_age():
        return time.time() - (DATA_DIR / "watchdog.alive").stat().st_mtime


def principal_sid(user_id):
    """Resolve the account identity, independent of the localized display name."""
    import win32security
    if user_id.upper().startswith("S-1-"):
        sid = win32security.ConvertStringSidToSid(user_id.upper())
    else:
        sid = win32security.LookupAccountName(None, user_id)[0]
    return win32security.ConvertSidToStringSid(sid)


def watchdog_checks(task, expected_executable, heartbeat_age):
    definition = task.Definition
    actions = definition.Actions
    action = actions.Item(1) if actions.Count == 1 else None
    return {
        "task_enabled": bool(task.Enabled),
        "single_action": actions.Count == 1,
        "expected_executable": action is not None and action.Path.casefold() == expected_executable.casefold(),
        "watchdog_argument": action is not None and action.Arguments.strip() == "watchdog",
        "system_account": principal_sid(definition.Principal.UserId) == "S-1-5-18",
        "successful_run": task.LastTaskResult == 0 or (task.LastTaskResult == 267009 and task.State == 4),
        "recent_heartbeat": 0 <= heartbeat_age < 150,
    }


def port_in_rule(value, port):
    for part in value.split(","):
        part = part.strip()
        if part == "*" or part == str(port):
            return True
        if "-" in part:
            try:
                low, high = map(int, part.split("-"))
                if low <= port <= high:
                    return True
            except ValueError:
                pass
    return False


def audit_logon_enabled():
    """Read effective Logon success/failure auditing through the native advanced audit API."""
    from ctypes import wintypes
    import uuid
    class GUID(ctypes.Structure):
        _fields_ = [("d1", wintypes.DWORD), ("d2", wintypes.WORD), ("d3", wintypes.WORD), ("d4", ctypes.c_ubyte * 8)]
    class AuditInfo(ctypes.Structure):
        _fields_ = [("subcategory", GUID), ("flags", wintypes.DWORD), ("category", GUID)]
    dll = ctypes.WinDLL("advapi32", use_last_error=True)
    dll.AuditQuerySystemPolicy.argtypes = [ctypes.POINTER(GUID), wintypes.ULONG, ctypes.POINTER(ctypes.POINTER(AuditInfo))]
    dll.AuditQuerySystemPolicy.restype = wintypes.BOOL
    dll.AuditFree.argtypes = [ctypes.c_void_p]
    dll.AuditFree.restype = None
    guid = GUID.from_buffer_copy(uuid.UUID("0cce9215-69ae-11d9-bed3-505054503030").bytes_le)
    info = ctypes.POINTER(AuditInfo)()
    if not dll.AuditQuerySystemPolicy(ctypes.byref(guid), 1, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return info.contents.flags & 3 == 3
    finally:
        dll.AuditFree(info)


def remote_allowed(value, ip):
    if value == "*":
        return True
    for part in value.split(","):
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(part.strip(), strict=False):
                return True
        except ValueError:
            pass
    return False
