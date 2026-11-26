"""End-to-end check of the actual frozen services on an isolated Actions Windows runner."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time

import httpx
import psutil
import win32service
import win32serviceutil
from rdp_guard.recovery import atomic_document, ServiceJournal
import win32api
import win32file
import win32net
import win32netcon
import win32security
import win32com.client
import pywintypes
from rdp_guard import __version__
from rdp_guard.firewall import FirewallEngine, owned
from rdp_guard.windows.firewall import WindowsFirewall
from rdp_guard.windows.collector import QUERIES

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


def check_installed_collectors():
    for _ in range(30):
        result = subprocess.run([cli, "status"], capture_output=True, text=True, timeout=20, check=True)
        state = json.loads(result.stdout)
        if all(state["collectors"].get(channel, {}).get("healthy") for channel in QUERIES):
            assert len(state["collectors"]) == 4
            assert "failure_sources" in state
            return
        time.sleep(1)
    raise AssertionError("Installed event subscriptions failed: " + json.dumps(state["collectors"]))


check_installed_collectors()
print("All four installed event subscriptions, including RdpCoreTS/140, are healthy.")

# Check the scheduler through the installed SYSTEM guard, not just a direct CLI watchdog call.
def check_watchdog_preflight():
    for _ in range(30):
        result = subprocess.run([cli, "preflight"], capture_output=True, text=True, timeout=20, check=True)
        preflight = json.loads(result.stdout)
        if preflight["checks"]["independent_watchdog"]:
            assert isinstance(preflight["sessions"], list)
            assert all("whitelisted" in session for session in preflight["sessions"])
            return
        time.sleep(1)
    health = subprocess.run([cli, "health"], capture_output=True, text=True, timeout=20)
    raise AssertionError("Installed scheduler watchdog check failed: " + health.stdout + health.stderr)


check_watchdog_preflight()
print("Installed scheduled watchdog and read-only CLI preflight passed.")


def check_installed_pairing(client, headers):
    """Exercise crypto and key storage inside the actual frozen SYSTEM service."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from rdp_guard.proxy_pairing import create_pairing, PairingAuthority, make_pairing_server
    import ipaddress

    addresses = [row.address for rows in psutil.net_if_addrs().values() for row in rows
                 if row.family == socket.AF_INET and not ipaddress.ip_address(row.address).is_loopback
                 and not ipaddress.ip_address(row.address).is_link_local
                 and not ipaddress.ip_address(row.address).is_unspecified]
    assert addresses, "Disposable runner needs one local IPv4 address for certificate enrollment"
    host = addresses[0]
    with socket.socket() as reservation:
        reservation.bind((host, 0))
        port = reservation.getsockname()[1]
    issued = []
    with tempfile.TemporaryDirectory(prefix="rdpguard-installed-pair-") as directory:
        key_directory = Path(directory) / "authority"
        document = create_pairing(key_directory, {
            "agent_url": f"https://{host}:{port}", "stream_id": "installed-ci",
            "backend_id": "windows-ci", "listener_ip": "192.0.2.45", "listener_port": 45451,
            "backend_ip": "192.0.2.46", "backend_port": 45451, "relay_ips": ["203.0.113.249"],
            "whitelist": ["198.51.100.253/32"], "protocols": ["tcp"],
        })
        authority = PairingAuthority(document, key_directory, issued.append)
        server = make_pairing_server(authority, host, port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            response = client.post("/api/rpc", headers=headers,
                                   json={"op": "proxy-pair-preview", "args": {"document": document}})
            assert response.status_code == 200, response.text
            computer = response.json()["computer"]
            request = {"op": "proxy-pair", "args": {"document": document, "trusted_relay": "203.0.113.249"}}
            rejected = client.post("/api/rpc", headers={"Origin": headers["Origin"]}, json=request)
            assert rejected.status_code == 401, "Enrollment mutation must require CSRF"
            response = client.post("/api/rpc", headers=headers, json=request)
            assert response.status_code == 200, response.text
            until = time.monotonic() + 40
            while time.monotonic() < until:
                response = client.post("/api/rpc", headers=headers, json={"op": "proxy-pair-status"})
                assert response.status_code == 200, response.text
                state = response.json()
                if state["state"] in ("paired", "failed", "cancelled"):
                    break
                time.sleep(0.2)
            assert state["state"] == "paired", state
            assert len(issued) == 1 and issued[0]["computer"] == computer
            assert authority.acknowledged and not state.get("handoff_pending"), state
            response = client.post("/api/rpc", headers=headers, json={"op": "proxy-status"})
            assert response.status_code == 200, response.text
            result = response.json()
            assert result["binding"]["mode"] == "monitor" and result["binding"]["enabled"]
            assert "203.0.113.249" in result["relay_ips"]
            key_root = Path(os.environ["ProgramData"]) / "RDPGuard" / "proxy" / ("enrollment-" + document["pairing_id"])
            cert = x509.load_pem_x509_certificate((key_root / "client.pem").read_bytes())
            assert cert.fingerprint(hashes.SHA256()).hex() == issued[0]["client_sha256"]
            assert (key_root / "client.key").is_file()
            for path in key_root.iterdir():
                assert document["token"].encode() not in path.read_bytes(), "Pairing token must not persist"
            response = client.post("/api/rpc", headers=headers, json={"op": "list-whitelist"})
            assert any(row["network"] == "203.0.113.249/32" for row in response.json())
            print("Frozen SYSTEM service imported pairing, enrolled over pinned TLS, saved a local key and monitor binding.")
        finally:
            response = client.post("/api/rpc", headers=headers,
                                   json={"op": "proxy-configure", "args": {"binding": {"enabled": False}}})
            assert response.status_code == 200, response.text
            server.shutdown()
            server.server_close()
            thread.join(10)
            authority.close()

# Read the actual registered definition and observe a timer-driven execution,
# not only the one immediate invocation performed by the installer.
scheduler = win32com.client.Dispatch("Schedule.Service")
scheduler.Connect()
task_folder = scheduler.GetFolder("\\")


def check_watchdog_schedule():
    task = task_folder.GetTask("RDPGuardRollback")
    assert task.Definition.Principal.LogonType == 5  # TASK_LOGON_SERVICE_ACCOUNT, inferred from the SYSTEM SID.
    triggers = list(task.Definition.Triggers)
    assert len(triggers) == 2 and {trigger.Type for trigger in triggers} == {1, 8}
    recurring = next(trigger for trigger in triggers if trigger.Type == 1)
    assert recurring.Enabled and recurring.Repetition.Interval == "PT1M"
    assert not recurring.Repetition.Duration and not recurring.EndBoundary
    assert next(trigger for trigger in triggers if trigger.Type == 8).Enabled
    return task.LastRunTime


last_run = check_watchdog_schedule()
wait_until = time.monotonic() + 90
while time.monotonic() < wait_until:
    task = task_folder.GetTask("RDPGuardRollback")
    if task.LastRunTime > last_run and task.LastTaskResult == 0 and task.State != 4:
        break
    time.sleep(1)
else:
    raise AssertionError("The registered watchdog did not run again on its minute timer")
print("Native watchdog has an unlimited minute trigger and a boot trigger; automatic repeat passed.")

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
    check_installed_pairing(client, headers)
    # State left by the Server 2012 R2 installation failure, after the user creates
    # the panel account: provisioned services and data, stopped services, missing task.
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "$ErrorActionPreference='Stop'; Stop-Service RDPGuardWeb; Stop-Service RDPGuardService; "
                    "Unregister-ScheduledTask -TaskName RDPGuardRollback -Confirm:$false"], check=True, timeout=60)
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
    check_watchdog_preflight()
    check_watchdog_schedule()
    print("Update.ps1 recovered the missing watchdog task and stopped services.")
    check_installed_collectors()
    response = client.post("/api/rpc", headers=headers, json={"op": "activate", "args": {"confirmation": "ENABLE RDP GUARD", "backup_access": True}})
    assert response.status_code == 400, "RDP is not configured on 33345; activation must fail"

# Actual service recovery on this disposable runner: both a clean stop and a
# killed process must recover, while the separate web process remains reachable.

recovery_dir = Path(os.environ["ProgramData"]) / "RDPGuard"
maintenance_path = recovery_dir / "maintenance.json"
atomic_document(maintenance_path, {"until": time.time() + 300})
win32serviceutil.StopService("RDPGuardService")
win32serviceutil.WaitForServiceStatus("RDPGuardService", win32service.SERVICE_STOPPED, 30)
with httpx.Client(base_url="http://127.0.0.1:8787", trust_env=False, timeout=15) as offline:
    response = offline.get("/")
    assert response.status_code == 503 and "unavailable.js" in response.text, response.text
    assert offline.get("/api/service-status").status_code == 200
maintenance_path.unlink()
subprocess.run([cli, "watchdog"], check=True, timeout=30)
win32serviceutil.WaitForServiceStatus("RDPGuardService", win32service.SERVICE_RUNNING, 30)
check_installed_collectors()
old_pid = psutil.win_service_get("RDPGuardService").pid()
assert old_pid and psutil.Process(old_pid).exe().lower() == str(root / "guardservice.exe").lower()
psutil.Process(old_pid).kill()
for _ in range(90):
    service_info = psutil.win_service_get("RDPGuardService")
    if service_info.status() == "running" and service_info.pid() and service_info.pid() != old_pid:
        break
    time.sleep(1)
else:
    raise AssertionError("SCM/watchdog did not recover the crashed protection service")
check_installed_collectors()
history = ServiceJournal(recovery_dir).recent()
assert any(row["event"] == "stop-requested" for row in history)
assert any(row["event"] == "unclean-exit" for row in history)
print("Stopped/crashed installed service recovered; offline web and durable lifecycle history passed.")

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
