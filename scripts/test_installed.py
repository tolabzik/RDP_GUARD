"""End-to-end check of the actual frozen services on an isolated Actions Windows runner."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

import httpx
import psutil
import win32service

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
    response = client.post("/api/rpc", headers=headers, json={"op": "activate", "args": {"confirmation": "ENABLE RDP GUARD", "backup_access": True}})
    assert response.status_code == 400, "RDP is not configured on 33345; activation must fail"

listeners = [c for c in psutil.net_connections(kind="tcp") if c.status == "LISTEN" and c.laddr.port == 8787]
assert listeners and all(c.laddr.ip == "127.0.0.1" for c in listeners)
subprocess.run(["sc.exe", "stop", "RDPGuardWeb"], check=True, capture_output=True)
time.sleep(3)
subprocess.run(["sc.exe", "stop", "RDPGuardService"], check=True, capture_output=True)
time.sleep(3)
subprocess.run([cli, "emergency-disable"], check=True)
assert (Path(os.environ["ProgramData"]) / "RDPGuard" / "emergency.disabled").exists()
print("Frozen services, IPC authentication, web login, CSRF command, loopback binding and independent emergency cleanup passed.")
