import ctypes
from datetime import datetime, timezone
import socket
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from conftest import event_xml
from rdp_guard.events import LSM, SECURITY
from rdp_guard.windows.platform import WindowsSafety
from rdp_guard.windows.sessions import FILETIME_EPOCH, SessionSourceResolver, _InfoEx, _Level1, connection_source

NOW = 1_800_000_000
PUBLIC_IP = "203.0.113.10"
REPORTED_IP = "192.168.30.110"
USER_SID = "S-1-5-21-1-2-3-500"


def source_xml(timestamp=NOW - 1, session_id=2, user=r"SERVER\administrator", ip=PUBLIC_IP, event_id=25):
    date = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
    <Provider Name="Microsoft-Windows-TerminalServices-LocalSessionManager"/><EventID>{event_id}</EventID>
    <EventRecordID>234</EventRecordID><TimeCreated SystemTime="{date}"/><Channel>{LSM}</Channel></System>
    <UserData><EventXML xmlns="Event_NS"><User>{user}</User><SessionID>{session_id}</SessionID>
    <Address>{ip}</Address></EventXML></UserData></Event>'''


def clock_info(connected=NOW - 2, logged_on=NOW - 600, current=NOW, session_id=2, state=0):
    return {"id": session_id, "state": state, "logon_ticks": FILETIME_EPOCH + logged_on * 10_000_000,
            "connect_ticks": FILETIME_EPOCH + connected * 10_000_000,
            "current_ticks": FILETIME_EPOCH + current * 10_000_000}


def test_wts_unicode_abi_matches_windows_sdk():
    assert ctypes.sizeof(_Level1) == 224
    assert ctypes.sizeof(_InfoEx) == 232
    assert _InfoEx.Data.offset == 8 and _Level1.LogonTime.offset == 160


@pytest.mark.parametrize("event_id", [21, 25])
@pytest.mark.parametrize("ip", [PUBLIC_IP, "2001:db8::10", "::ffff:203.0.113.10"])
def test_source_is_server_recorded_address_of_current_session(event_id, ip):
    result = connection_source(source_xml(ip=ip, event_id=event_id), 2, "administrator", "SERVER", NOW - 2, NOW)
    assert result["ip"] == (PUBLIC_IP if ip.startswith("::ffff:") else ip)
    assert result["ip_source"] == f"LSM/{event_id}"
    assert result["source_record_id"] == 234


@pytest.mark.parametrize("changes", [
    {"session_id": 3}, {"user": r"OTHER\administrator"}, {"user": r"SERVER\other"},
    {"timestamp": NOW - 3}, {"timestamp": NOW + 1}, {"ip": "LOCAL"}, {"ip": "-"},
    {"event_id": 23},
])
def test_other_or_stale_connection_cannot_supply_an_admin_source(changes):
    with pytest.raises(RuntimeError):
        connection_source(source_xml(**changes), 2, "administrator", "SERVER", NOW - 2, NOW)


def test_network_authentication_event_cannot_bind_a_session():
    with pytest.raises(RuntimeError):
        connection_source(event_xml(event_id=4625, logon_type=3), 2, "administrator", "SERVER", NOW - 2, NOW)


def test_wrong_provider_and_ambiguous_userdata_rejected():
    bad_provider = source_xml().replace('Name="Microsoft-Windows-TerminalServices-LocalSessionManager"', 'Name="Other"')
    with pytest.raises(ValueError):
        connection_source(bad_provider, 2, "administrator", "SERVER", NOW - 2, NOW)
    duplicate = source_xml().replace("</SessionID>", "</SessionID><SessionID>3</SessionID>")
    with pytest.raises(RuntimeError, match="Ambiguous"):
        connection_source(duplicate, 2, "administrator", "SERVER", NOW - 2, NOW)


def test_binding_cache_is_invalidated_on_reconnect_and_does_not_fall_back():
    info = clock_info()
    read_event = Mock(return_value=source_xml())
    resolver = SessionSourceResolver(lambda _: dict(info), read_event, lambda: NOW + 100)
    assert resolver.resolve(2, USER_SID, "administrator", "SERVER")["ip"] == PUBLIC_IP
    resolver.resolve(2, USER_SID, "administrator", "SERVER")
    assert read_event.call_count == 1
    info.update(clock_info(connected=NOW + 10, current=NOW + 100))
    with pytest.raises(RuntimeError, match="current connection"):
        resolver.resolve(2, USER_SID, "administrator", "SERVER")
    assert 2 not in resolver.cache
    read_event.return_value = source_xml(timestamp=NOW + 11, ip="198.51.100.9")
    assert resolver.resolve(2, USER_SID, "administrator", "SERVER")["ip"] == "198.51.100.9"


def test_reused_session_id_cannot_reuse_prior_login_proof():
    resolver = SessionSourceResolver(lambda _: clock_info(connected=NOW, logged_on=NOW, current=NOW + 10),
                                     lambda _: source_xml(), lambda: NOW + 10)
    with pytest.raises(RuntimeError, match="current connection"):
        resolver.resolve(2, USER_SID, "administrator", "SERVER")


@pytest.mark.parametrize("phase", ["identity", "proof"])
def test_reconnect_during_identity_or_event_lookup_is_rejected(phase):
    first, second = clock_info(), clock_info(connected=NOW, current=NOW + 1)
    read_clock = Mock(side_effect=[second] if phase == "identity" else [first, second])
    resolver = SessionSourceResolver(read_clock, lambda _: source_xml(), lambda: NOW + 1)
    with pytest.raises(RuntimeError, match="session changed"):
        resolver.resolve(2, USER_SID, "administrator", "SERVER", expected_clock=first)


@pytest.mark.parametrize("change", [{"state": 4}, {"connect_ticks": 0}, {"logon_ticks": 0}, {"id": 3}])
def test_unavailable_session_clock_never_falls_back_to_client_address(change):
    read_event = Mock(return_value=source_xml())
    resolver = SessionSourceResolver(lambda _: clock_info() | change, read_event, lambda: NOW)
    with pytest.raises(RuntimeError, match="timestamps"):
        resolver.resolve(2, USER_SID, "administrator", "SERVER")
    read_event.assert_not_called()


@pytest.fixture
def nat_adapter(monkeypatch):
    state = {"info": clock_info(), "xml": source_xml(), "now": NOW}
    values = {16: 2, 5: "administrator", 7: "SERVER",
              14: {"AddressFamily": socket.AF_INET, "Address": b"\0\0" + socket.inet_aton(REPORTED_IP) + b"\0" * 14}}
    ts = SimpleNamespace(WTSActive=0, WTSClientProtocolType=16, WTSUserName=5, WTSDomainName=7, WTSClientAddress=14,
        WTSEnumerateSessions=lambda *args: [{"State": 0, "SessionId": 2}],
        WTSQuerySessionInformation=lambda server, sid, field: values[field], WTSQueryUserToken=lambda sid: Mock())
    security = SimpleNamespace(TokenGroups=2, TokenUser=1,
        GetTokenInformation=lambda token, field: [("S-1-5-32-544", 16)] if field == 2 else (USER_SID, 0),
        ConvertSidToStringSid=lambda sid: sid)
    monkeypatch.setitem(sys.modules, "win32ts", ts)
    monkeypatch.setitem(sys.modules, "win32security", security)
    safety = WindowsSafety()
    safety._sources = SessionSourceResolver(lambda _: dict(state["info"]), lambda _: state["xml"], lambda: state["now"])
    return safety, state


def test_nat_preflight_and_reconnect_use_existing_public_whitelist(guard, nat_adapter):
    safety, state = nat_adapter
    checks = dict(guard.safety.checks)
    safety.health = lambda port: checks | {"errors": []}
    guard.safety = safety
    guard.dispatch("whitelist-add", {"network": PUBLIC_IP}, "test")
    result = guard.preflight()
    assert result["ready"]
    assert result["sessions"][0]["ip"] == PUBLIC_IP
    assert result["sessions"][0]["client_reported_ip"] == REPORTED_IP
    assert result["sessions"][0]["whitelisted"]
    guard.dispatch("activate", {"confirmation": "ENABLE RDP GUARD", "backup_access": True}, "test")
    guard.clock.now += 11
    state.update(info=clock_info(connected=NOW + 10, current=NOW + 11), xml=source_xml(timestamp=NOW + 11), now=NOW + 11)
    guard.ingest(event_xml(timestamp=NOW + 11, event_id=4624, ip=PUBLIC_IP, username="administrator"), SECURITY, "nat-reconnect")
    assert guard.confirm_active("test")["confirmed"]
    assert guard.store.rows("SELECT network FROM whitelist") == [{"network": PUBLIC_IP + "/32"}]


def test_private_client_ip_cannot_satisfy_public_source_whitelist(guard, nat_adapter):
    safety, _ = nat_adapter
    checks = dict(guard.safety.checks)
    safety.health = lambda port: checks | {"errors": []}
    guard.safety = safety
    guard.dispatch("whitelist-add", {"network": REPORTED_IP}, "test")
    assert not guard.preflight()["checks"]["administrative_whitelist"]


def test_missing_source_event_reports_error_and_prevents_activation(guard, nat_adapter):
    safety, state = nat_adapter
    checks = dict(guard.safety.checks)
    safety.health = lambda port: checks | {"errors": []}
    guard.safety = safety
    state["xml"] = source_xml(timestamp=NOW - 10)
    result = guard.preflight()
    assert not result["ready"] and not result["checks"]["session_inventory"]
    assert "current connection" in result["session_error"]
    assert guard.mode == "MONITOR ONLY"
