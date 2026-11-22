"""End-to-end check of the actual frozen services on an isolated Actions Windows runner."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

import httpx
import psutil
import win32service
import win32api
import win32file
import win32net
import win32netcon
import win32security
import pywintypes
from rdp_guard import __version__
from rdp_guard.firewall import FirewallEngine, owned
from rdp_guard.windows.firewall import WindowsFirewall

if os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Only run this integration test in a disposable GitHub Actions runner")

root = Path(os.environ["ProgramFiles"]) / "RDPGuard"
cli = str(root / "rdpguard.exe")
password = secrets.token_urlsafe(32)
subprocess.run([cli, "init-admin", "--username", "ci-admin", "--password-stdin"], input=password + "\n", text=True, check=True)
for _ in range(45):
    status = subprocess.run([cli, "status"], capture_output=True, text=True)
    if status.returncode == 0:
        break
    time.sleep(1)
else:
    raise RuntimeError(status.stderr)
assert json.loads(status.stdout)["mode"] == "MONITOR ONLY"

# A normal local user must not be able to bypass the web boundary through the pipe or database.
username = "rdpg-ci-" + secrets.token_hex(3)
user_password = secrets.token_urlsafe(32) + "aA1!"
win32net.NetUserAdd(None, 1, {"name": username, "password": user_password,
    "priv": win32netcon.USER_PRIV_USER, "home_dir": "", "comment": "Disposable RDP Guard CI",
    "flags": win32netcon.UF_SCRIPT | win32netcon.UF_DONT_EXPIRE_PASSWD, "script_path": ""})
try:
    try:
        win32net.NetLocalGroupAddMembers(None, "Users", 3, [{"domainandname": username}])
    except pywintypes.error as exc:
        if exc.winerror != 1378:  # NetUserAdd may have already assigned the default Users group.
            raise
    token = win32security.LogonUser(username, ".", user_password, win32security.LOGON32_LOGON_INTERACTIVE,
                                   win32security.LOGON32_PROVIDER_DEFAULT)
    try:
        win32security.ImpersonateLoggedOnUser(token)
        try:
            try:
                handle = win32file.CreateFile(r"\\.\pipe\RDPGuard.v1", 0x100003, 0, None, 3, 0, None)
            except pywintypes.error as exc:
                assert exc.winerror == 5, exc
            else:
                handle.Close()
                raise AssertionError("Ordinary user could open the privileged named pipe")
            try:
                (Path(os.environ["ProgramData"]) / "RDPGuard" / "guard.db").read_bytes()
            except PermissionError:
                pass
            else:
                raise AssertionError("Ordinary user could read the protected database")
        finally:
            win32security.RevertToSelf()
    finally:
        win32api.CloseHandle(token)
finally:
    win32net.NetUserDel(None, username)

manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
service = win32service.OpenService(manager, "RDPGuardWeb", win32service.SERVICE_QUERY_CONFIG)
try:
    assert win32service.QueryServiceConfig(service)[7].lower() == "nt authority\\localservice"
finally:
    win32service.CloseServiceHandle(service)
    win32service.CloseServiceHandle(manager)

with httpx.Client(base_url="http://127.0.0.1:8787", trust_env=False, timeout=15) as client:
    for _ in range(45):
        try:
            if client.get("/login").status_code == 200:
                break
        except httpx.ConnectError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("Web service did not start")
    assert client.get("/api/session").status_code == 401
    headers = {"Origin": "http://127.0.0.1:8787"}
    response = client.post("/api/login", headers=headers, json={"username": "ci-admin", "password": password})
    assert response.status_code == 200, response.text
    headers["X-CSRF-Token"] = client.get("/api/session").json()["csrf"]
    response = client.post("/api/rpc", headers=headers, json={"op": "whitelist-add", "args": {"network": "198.51.100.253", "comment": "CI"}})
    assert response.status_code == 200, response.text
    assert client.get("/").status_code == 200
    response = client.post("/api/rpc", headers=headers, json={"op": "status"})
    assert response.status_code == 200, response.text
    assert response.json()["mode"] == "MONITOR ONLY"
    # The browser sends status/events together. Exercise the actual LocalService -> SYSTEM
    # boundary repeatedly, including more clients than the pipe server's four workers.
    def dashboard_call(operation):
        response = client.post("/api/rpc", headers=headers, json={"op": operation})
        assert response.status_code == 200, response.text
        result = response.json()
        if operation == "status":
            assert result["mode"] == "MONITOR ONLY"
        return result
    for workers in (2, 8):
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for _ in range(10):
                list(pool.map(dashboard_call, ["status", "events"] * (workers // 2)))
    status = subprocess.run([cli, "status"], capture_output=True, text=True, timeout=20, check=True)
    assert json.loads(status.stdout)["mode"] == "MONITOR ONLY"
    print("100 concurrent dashboard RPC requests and subsequent CLI status passed.")
    # Exercise the shipped update path on an existing database and real service processes.
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                    str(Path(__file__).with_name("Update.ps1"))], check=True, timeout=120)
    for _ in range(30):
        try:
            response = client.post("/api/rpc", headers=headers, json={"op": "status"})
            if response.status_code == 200:
                break
        except httpx.TransportError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("Updated services did not resume the existing session")
    assert response.json()["version"] == __version__
    assert response.json()["mode"] == "MONITOR ONLY" and response.json()["emergency_disabled"]
    response = client.post("/api/login", headers=headers, json={"username": "ci-admin", "password": password})
    assert response.status_code == 200, "Update must preserve the administrator's password"
    headers["X-CSRF-Token"] = client.get("/api/session").json()["csrf"]
    response = client.post("/api/rpc", headers=headers, json={"op": "list-whitelist"})
    assert response.status_code == 200, response.text
    assert any(row["network"] in ("198.51.100.253", "198.51.100.253/32") and row["comment"] == "CI"
               for row in response.json())
    assert list((Path(os.environ["ProgramData"]) / "RDPGuard").glob("backup-*/guard.db"))
    print("Update.ps1 preserved login, session, whitelist and backup; protection remains disabled.")
    response = client.post("/api/rpc", headers=headers, json={"op": "activate", "args": {"confirmation": "ENABLE RDP GUARD", "backup_access": True}})
    assert response.status_code == 400, "RDP is not configured on 33345; activation must fail"

listeners = [c for c in psutil.net_connections(kind="tcp") if c.status == "LISTEN" and c.laddr.port == 8787]
assert listeners and all(c.laddr.ip == "127.0.0.1" for c in listeners)
subprocess.run(["sc.exe", "stop", "RDPGuardWeb"], check=True, capture_output=True)
time.sleep(3)
subprocess.run(["sc.exe", "stop", "RDPGuardService"], check=True, capture_output=True)
time.sleep(3)
backend = WindowsFirewall()
FirewallEngine(backend).reconcile(["198.51.100.254"], 33345)
data_dir = Path(os.environ["ProgramData"]) / "RDPGuard"
(data_dir / "active-lease.json").write_text(json.dumps({"heartbeat": time.time() - 100, "deadline": time.time() - 1}), encoding="utf-8")
subprocess.run([cli, "watchdog"], check=True)
assert not any(owned(rule) for rule in backend.list_rules()), "Independent watchdog must remove its scoped rules"
subprocess.run([cli, "emergency-disable"], check=True)
assert (Path(os.environ["ProgramData"]) / "RDPGuard" / "emergency.disabled").exists()
print("Frozen services, IPC authentication, web login, CSRF command, loopback binding and independent emergency cleanup passed.")
