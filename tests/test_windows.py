"""Native tests run only in an explicitly opted-in disposable Windows CI machine."""
import os
import sys

import pytest
from rdp_guard.windows.collector import QUERIES

pytestmark = [pytest.mark.windows, pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("RDP_GUARD_NATIVE_TESTS") != "1",
    reason="Native firewall tests require an explicitly opted-in isolated Windows host")]


@pytest.mark.parametrize("channel", QUERIES)
def test_native_event_subscription_and_bookmark(channel):
    import win32event
    import win32evtlog
    signal = win32event.CreateEvent(None, False, False, None)
    bookmark = win32evtlog.EvtCreateBookmark(None)
    subscription = None
    try:
        xml = win32evtlog.EvtRender(bookmark, win32evtlog.EvtRenderBookmark)
        assert "BookmarkList" in xml
        subscription = win32evtlog.EvtSubscribe(channel, win32evtlog.EvtSubscribeToFutureEvents,
            SignalEvent=signal, Query=QUERIES[channel])
        for event in win32evtlog.EvtNext(subscription, 1, 0, 0):
            event.Close()
    finally:
        if subscription:
            subscription.Close()
        bookmark.Close()
        signal.Close()


def test_native_proxy_export_is_read_only_and_handles_absent_history():
    import json
    import time
    from rdp_guard.proxy_evidence import CHANNEL, WINDOWS_SCHEMA, instant
    from rdp_guard.windows.proxy_export import NativeProxyExporter, utc

    exporter = NativeProxyExporter()
    snapshot = exporter._snapshot()
    # These assertions expose missing APIs, wrong property constants/signatures,
    # or an incorrect (value, EVT variant type) unpacking even on an empty log.
    assert snapshot["channel"] == CHANNEL
    assert type(snapshot["is_enabled"]) is bool, snapshot
    assert snapshot["log_mode"] in {"Circular", "Retain", "AutoBackup"}, snapshot
    for name in ("maximum_size_bytes", "record_count", "oldest_record_number"):
        assert type(snapshot[name]) is int and snapshot[name] >= 0, snapshot
    assert snapshot["maximum_size_bytes"] > 0
    assert "Native channel metadata could not be read" not in snapshot["errors"]
    # Exercise the forward-direction boundary query without the snapshot's
    # deliberately tolerant empty-history error handling.
    assert len(exporter._query("*", 1, oldest=True)) <= 1

    # A bounded query is valid even if no RDP authentication happened in CI.
    end = time.time() - 2
    query = ("*[System[(EventID=131 or EventID=140) and TimeCreated["
             f"@SystemTime >= '{utc(end - 30)}' and @SystemTime < '{utc(end)}']]]")
    records = exporter._query(query, 2)
    assert isinstance(records, list) and len(records) <= 2
    assert all(isinstance(raw, str) and "<Event" in raw for raw in records)

    document = exporter.export(utc(end - 30), utc(end), lookback_seconds=5, max_events=16)
    assert document["schema"] == WINDOWS_SCHEMA
    assert document["window_end_exclusive"] is True
    assert document["max_events"] == 16 and document["lookback_seconds"] == 5
    assert 0 <= document["queried_event_count"] <= 17
    assert document["event_count"] == len(document["events"]) <= 16
    assert document["errors"] == (["Native event query exceeded max_events"] if document["truncated"] else [])
    assert document["complete"] is (not document["truncated"])
    assert instant(document["query_start_utc"]) < instant(document["requested_start_utc"]) < instant(document["requested_end_utc"])
    json.dumps(document, allow_nan=False)
    coverage = document["log_coverage"]
    assert coverage["status"] in {"retained", "insufficient", "unknown"}
    for boundary_snapshot in (coverage["before"], coverage["after"]):
        assert type(boundary_snapshot["is_enabled"]) is bool
        assert type(boundary_snapshot["record_count"]) is int
        assert "Native channel metadata could not be read" not in boundary_snapshot["errors"]
        if boundary_snapshot["oldest"] is None or boundary_snapshot["newest"] is None:
            assert coverage["status"] != "retained"
        if boundary_snapshot["is_enabled"] is False:
            assert coverage["status"] != "retained"


def test_native_firewall_roundtrip_and_empty_cleanup():
    from rdp_guard.firewall import FirewallEngine, owned
    from rdp_guard.windows.firewall import WindowsFirewall
    from rdp_guard.windows.platform import firewall_mutex, require_admin
    require_admin()
    backend = WindowsFirewall()
    engine = FirewallEngine(backend)
    before = {r.name for r in backend.list_rules()}
    assert not any(owned(r) for r in backend.list_rules()), "Refuse tests on an existing RDP Guard installation"
    with firewall_mutex():
        try:
            engine.reconcile(["198.51.100.254", "2001:db8::ffff"], 33345)
            rules = [r for r in backend.list_rules() if owned(r)]
            assert len(rules) == 2 and all(r.port == 33345 for r in rules)
            engine.reconcile(["198.51.100.253"], 33345)
            engine.reconcile([], 33345)
            assert not any(owned(r) for r in backend.list_rules())
        finally:
            engine.clear()
    assert {r.name for r in backend.list_rules()} == before


def test_web_rejects_administrative_process():
    from rdp_guard.windows.platform import require_unprivileged
    with pytest.raises(PermissionError):
        require_unprivileged()


def test_native_logon_audit_api():
    from rdp_guard.windows.platform import audit_logon_enabled
    assert isinstance(audit_logon_enabled(), bool)


def test_native_system_principal_resolution_uses_machine_locale():
    import win32security
    from rdp_guard.windows.platform import principal_sid
    sid = win32security.ConvertStringSidToSid("S-1-5-18")
    name, domain, _ = win32security.LookupAccountSid(None, sid)
    assert principal_sid(name) == "S-1-5-18"
    assert principal_sid(domain + "\\" + name) == "S-1-5-18"
    assert principal_sid("S-1-5-18") == "S-1-5-18"
    other = win32security.ConvertStringSidToSid("S-1-5-19")
    name, domain, _ = win32security.LookupAccountSid(None, other)
    assert principal_sid(domain + "\\" + name) != "S-1-5-18"


def test_native_extended_session_clock():
    import ctypes
    import time
    import win32ts
    from rdp_guard.windows.sessions import FILETIME_EPOCH, session_clock
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ProcessIdToSessionId.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    kernel.ProcessIdToSessionId.restype = ctypes.c_int
    session_id = ctypes.c_uint32()
    assert kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id))
    result = session_clock(session_id.value)
    assert result["id"] == session_id.value
    assert result["state"] == win32ts.WTSQuerySessionInformation(None, session_id.value, win32ts.WTSConnectState)
    if result["current_ticks"]:
        assert abs((result["current_ticks"] - FILETIME_EPOCH) / 10_000_000 - time.time()) < 30


def test_native_session_source_xpath_and_empty_result():
    from rdp_guard.windows.sessions import latest_connection_event
    with pytest.raises(RuntimeError, match="No server RDP connection event"):
        latest_connection_event(0xFFFFFFFE)


def test_native_named_pipe_client_connects_before_accept():
    import subprocess
    from pathlib import Path
    # The old implementation can also hang while cancelling a connect that was never pending.
    # Isolate it so a regression fails promptly instead of hanging the entire Windows job.
    code = "import runpy; runpy.run_path(" + repr(str(Path(__file__).resolve())) + ")[\"_preconnected_roundtrip\"]()"
    subprocess.run([sys.executable, "-c", code], check=True, timeout=10)


def _preconnected_roundtrip():
    """CreateFile can complete before ConnectNamedPipe has started its overlapped wait."""
    import uuid
    import win32con
    import win32file
    import win32pipe
    from rdp_guard.windows import ipc
    name = r"\\.\pipe\RDPGuard.Test." + uuid.uuid4().hex
    server = win32pipe.CreateNamedPipe(name,
        win32pipe.PIPE_ACCESS_DUPLEX | win32con.FILE_FLAG_OVERLAPPED,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | 0x8,
        1, 65536, 65536, 5000, None)
    client = None
    try:
        # Deliberately connect before the server accepts: this must not wait for an event.
        client = win32file.CreateFile(name, 0x12019B, 0, None, win32con.OPEN_EXISTING,
                                     win32con.FILE_FLAG_OVERLAPPED, None)
        assert ipc._overlapped(server, lambda ov: win32pipe.ConnectNamedPipe(server, ov), timeout=500) == 0
        ipc.write_message(client, {"op": "status"}, ipc.MAX_REQUEST)
        assert ipc.read_message(server, ipc.MAX_REQUEST) == {"op": "status"}
    finally:
        if client:
            client.Close()
        server.Close()


def test_native_named_pipe_identity_and_message_roundtrip(monkeypatch):
    import threading
    import uuid
    import pywintypes
    import win32con
    import win32file
    import win32pipe
    import win32security
    from rdp_guard.windows import ipc
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)", 1)
    name = r"\\.\pipe\RDPGuard.Test." + uuid.uuid4().hex
    monkeypatch.setattr(ipc, "PIPE_NAME", name)
    monkeypatch.setattr(ipc, "security_attributes", lambda: (attributes, "S-1-5-80-0"))
    stop = threading.Event()
    def dispatch(request, identity):
        assert identity["role"] == "admin"
        return {"echo": request["op"], "role": identity["role"]}
    server = ipc.PipeServer(dispatch, stop)
    server.start()
    assert server.ready.wait(10) and not server.error
    handle = None
    try:
        handle = win32file.CreateFile(name, 0x12019B, 0, None, win32con.OPEN_EXISTING,
                                     win32con.FILE_FLAG_OVERLAPPED | 0x00100000 | 0x00010000, None)
        win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        ipc.write_message(handle, {"op": "status"}, ipc.MAX_REQUEST)
        response = ipc.read_message(handle, ipc.MAX_RESPONSE)
        assert response == {"ok": True, "result": {"echo": "status", "role": "admin"}}
        ipc.write_message(handle, {"ack": True}, 1024)
    finally:
        if handle:
            handle.Close()
        stop.set()
        server.join(15)
    assert not server.is_alive() and not server.error


@pytest.mark.parametrize("clients", [2, 8])
def test_native_named_pipe_concurrent_clients(monkeypatch, clients):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    import uuid
    import pywintypes
    import win32security
    from rdp_guard.windows import ipc
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)", 1)
    monkeypatch.setattr(ipc, "PIPE_NAME", r"\\.\pipe\RDPGuard.Test." + uuid.uuid4().hex)
    monkeypatch.setattr(ipc, "security_attributes", lambda: (attributes, "S-1-5-80-0"))
    # This test has no installed SCM service; the frozen-service smoke test covers verification.
    monkeypatch.setattr(ipc, "verify_server", lambda handle: None)
    stop = threading.Event()
    seen = []
    def dispatch(request, identity):
        assert identity["role"] == "admin"
        seen.append(request["id"])
        return request["id"]
    server = ipc.PipeServer(dispatch, stop)
    server.start()
    assert server.ready.wait(10) and not server.error
    try:
        with ThreadPoolExecutor(max_workers=clients) as pool:
            for batch in range(20):
                barrier = threading.Barrier(clients)
                def request(number):
                    barrier.wait(timeout=10)
                    return ipc.PipeClient().call({"id": number})
                numbers = list(range(batch * clients, (batch + 1) * clients))
                assert list(pool.map(request, numbers)) == numbers
        assert sorted(seen) == list(range(20 * clients))  # No dropped or replayed requests.
    finally:
        stop.set()
        server.join(15)
    assert not server.is_alive() and not server.error
