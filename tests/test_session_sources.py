import ctypes
from datetime import datetime, timezone
import json
import socket
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from conftest import event_xml
from rdp_guard.events import LSM, SECURITY
from rdp_guard.windows.platform import SESSION_RETRY_SECONDS, WindowsSafety
from rdp_guard.windows.sessions import FILETIME_EPOCH, SessionSourceResolver, _InfoEx, _Level1, connection_source

NOW = 1_800_000_000
PUBLIC_IP = "203.0.113.10"
REPORTED_IP = "192.168.30.110"
USER_SID = "S-1-5-21-1-2-3-500"


class RetryClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []
        self.on_sleep = lambda: None

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        assert seconds > 0
        self.sleeps.append(seconds)
        self.now += seconds
        self.on_sleep()


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
    retry_clock = RetryClock()
    state = {"info": clock_info(), "xml": source_xml(), "now": NOW, "retry_clock": retry_clock}
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
    safety = WindowsSafety(monotonic=retry_clock, sleep=retry_clock.sleep)
    safety._sources = SessionSourceResolver(lambda _: dict(state["info"]), lambda _: state["xml"], lambda: state["now"])
    return safety, state


@pytest.mark.parametrize("event_id,logon_type", [(21, 10), (25, 7), (25, None)])
def test_nat_preflight_and_reconnect_use_existing_public_whitelist(guard, nat_adapter, event_id, logon_type):
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
    state.update(info=clock_info(connected=NOW + 10, current=NOW + 11),
                 xml=source_xml(timestamp=NOW + 11, event_id=event_id), now=NOW + 11)
    if logon_type is not None:
        guard.ingest(event_xml(timestamp=NOW + 11, event_id=4624, logon_type=logon_type,
                               ip=PUBLIC_IP, username="administrator"), SECURITY, "nat-reconnect")
    assert guard.dispatch("confirm-active", {}, "test")["confirmed"]
    lease = json.loads(guard.lease_path.read_text())
    assert lease["confirmed"] and lease["deadline"] is None
    audit = guard.store.rows("SELECT detail FROM audit WHERE action='activation-confirmed'")
    detail = json.loads(audit[0]["detail"])
    assert detail["ip_source"] == f"LSM/{event_id}" and detail["source_record_id"] == 234
    assert detail["id"] == 2 and detail["connected_at"] == NOW + 10
    assert guard.store.rows("SELECT network FROM whitelist") == [{"network": PUBLIC_IP + "/32"}]


@pytest.fixture
def pending_nat_activation(guard, nat_adapter):
    safety, state = nat_adapter
    checks = dict(guard.safety.checks)
    safety.health = lambda port: checks | {"errors": []}
    guard.safety = safety
    guard.dispatch("whitelist-add", {"network": PUBLIC_IP}, "test")
    guard.dispatch("activate", {"confirmation": "ENABLE RDP GUARD", "backup_access": True}, "test")
    guard.clock.now += 11
    state.update(info=clock_info(connected=NOW + 10, current=NOW + 11),
                 xml=source_xml(timestamp=NOW + 11), now=NOW + 11)
    return state


@pytest.mark.parametrize("event_id,logon_type", [(4624, 7), (4624, 10), (4778, 0)])
def test_auth_event_without_new_wts_connection_cannot_confirm(guard, pending_nat_activation, event_id, logon_type):
    state = pending_nat_activation
    # Even an LSM record delivered after activation is insufficient if WTS still
    # identifies a connection established before activation.
    state["info"] = clock_info(current=NOW + 11)
    guard.safety._sources.cache.clear()
    guard.ingest(event_xml(timestamp=NOW + 11, event_id=event_id, logon_type=logon_type,
                           ip=PUBLIC_IP, username="administrator"), SECURITY, "unbound-auth")
    with pytest.raises(ValueError):
        guard.dispatch("confirm-active", {}, "test")
    assert not json.loads(guard.lease_path.read_text())["confirmed"]


@pytest.mark.parametrize("changes", [
    {"session_id": 3}, {"user": r"OTHER\administrator"}, {"user": r"SERVER\other"},
    {"timestamp": NOW - 1}, {"timestamp": NOW + 12}, {"ip": "LOCAL"}, {"event_id": 24},
])
def test_unbound_reconnect_event_cannot_confirm(guard, pending_nat_activation, changes):
    pending_nat_activation["xml"] = source_xml(**({"timestamp": NOW + 11} | changes))
    with pytest.raises(RuntimeError, match="Cannot verify"):
        guard.dispatch("confirm-active", {}, "test")
    assert not json.loads(guard.lease_path.read_text())["confirmed"]


def test_reconnect_from_new_unlisted_address_cannot_confirm(guard, pending_nat_activation):
    pending_nat_activation["xml"] = source_xml(timestamp=NOW + 11, ip="198.51.100.9")
    with pytest.raises(ValueError):
        guard.dispatch("confirm-active", {}, "test")
    assert guard.store.rows("SELECT network FROM whitelist") == [{"network": PUBLIC_IP + "/32"}]


@pytest.mark.parametrize("state", [4, 5])
def test_disconnected_session_cannot_confirm(guard, pending_nat_activation, state):
    pending_nat_activation["info"]["state"] = state
    with pytest.raises(RuntimeError, match="Cannot verify"):
        guard.dispatch("confirm-active", {}, "test")


@pytest.mark.parametrize("kind", ["console", "non_admin"])
def test_only_administrative_rdp_sessions_can_confirm(guard, pending_nat_activation, monkeypatch, kind):
    if kind == "console":
        ts = sys.modules["win32ts"]
        query = ts.WTSQuerySessionInformation
        monkeypatch.setattr(ts, "WTSQuerySessionInformation",
                            lambda server, sid, field: 0 if field == 16 else query(server, sid, field))
    else:
        security = sys.modules["win32security"]
        query = security.GetTokenInformation
        monkeypatch.setattr(security, "GetTokenInformation",
                            lambda token, field: [] if field == 2 else query(token, field))
    with pytest.raises(ValueError):
        guard.dispatch("confirm-active", {}, "test")


def test_connection_at_activation_boundary_is_not_new(guard, pending_nat_activation):
    pending_nat_activation["info"] = clock_info(connected=NOW, current=NOW + 11)
    with pytest.raises(ValueError):
        guard.dispatch("confirm-active", {}, "test")


def test_confirmation_expiring_during_session_lookup_is_rejected(guard, pending_nat_activation):
    read_event = guard.safety._sources.read_event

    def slow_read(session_id):
        guard.clock.now = NOW + 181
        return read_event(session_id)

    guard.safety._sources.read_event = slow_read
    with pytest.raises(ValueError, match="expired"):
        guard.dispatch("confirm-active", {}, "test")
    assert not json.loads(guard.lease_path.read_text())["confirmed"]


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


def test_healthy_session_inventory_has_no_retry_delay(nat_adapter):
    safety, state = nat_adapter
    assert safety.sessions()["healthy"]
    assert state["retry_clock"].sleeps == []


@pytest.mark.parametrize("ip", [PUBLIC_IP, "198.51.100.9"])
def test_tick_waits_for_current_lsm_record_then_checks_reconnect_whitelist(guard, nat_adapter, ip):
    safety, state = nat_adapter
    checks = dict(guard.safety.checks)
    safety.health = lambda port: checks | {"errors": []}
    guard.safety = safety
    guard.dispatch("whitelist-add", {"network": PUBLIC_IP}, "test")
    guard.dispatch("activate", {"confirmation": "ENABLE RDP GUARD", "backup_access": True}, "test")
    deadline = json.loads(guard.lease_path.read_text())["deadline"]
    guard.clock.now += 11
    state.update(info=clock_info(connected=NOW + 10, current=NOW + 11), now=NOW + 11)
    # WTS already changed; the newest readable LSM record is still the old one.
    retry_clock = state["retry_clock"]
    read_event = Mock(wraps=safety._sources.read_event)
    safety._sources.read_event = read_event

    def publish_current_event():
        assert not guard.firewall.backend.list_rules()
        assert not json.loads(guard.lease_path.read_text())["confirmed"]
        if retry_clock.now >= 0.2:
            state["xml"] = source_xml(timestamp=NOW + 10.003, ip=ip).replace(
                "<EventRecordID>234</EventRecordID>", "<EventRecordID>235</EventRecordID>")

    retry_clock.on_sleep = publish_current_event
    guard.tick(force=True)
    assert read_event.call_count == 3 and retry_clock.now == pytest.approx(0.2)
    assert guard.mode == "ACTIVE"
    assert json.loads(guard.lease_path.read_text())["deadline"] == deadline
    assert safety.sessions()["sessions"][0]["source_record_id"] == 235
    if ip == PUBLIC_IP:
        assert guard.dispatch("confirm-active", {}, "test")["confirmed"]
    else:
        with pytest.raises(ValueError, match="Не найдено"):
            guard.dispatch("confirm-active", {}, "test")
        assert not json.loads(guard.lease_path.read_text())["confirmed"]
    assert guard.store.rows("SELECT network FROM whitelist") == [{"network": PUBLIC_IP + "/32"}]


def test_session_change_retries_full_inventory_with_fresh_identity(nat_adapter):
    safety, state = nat_adapter
    old, new = clock_info(), clock_info(connected=NOW + 10, current=NOW + 11)
    reads = []

    def changing_clock(session_id):
        reads.append(session_id)
        return old if len(reads) == 1 else new

    safety._sources.read_clock = changing_clock
    state.update(xml=source_xml(timestamp=NOW + 11), now=NOW + 11)
    result = safety.sessions()
    assert result["healthy"]
    assert result["sessions"][0]["connected_at"] == NOW + 10
    assert len(reads) == 5 and len(state["retry_clock"].sleeps) == 1


def test_disconnect_during_inventory_is_reenumerated(nat_adapter, monkeypatch):
    safety, state = nat_adapter
    ts = sys.modules["win32ts"]
    enumerate_sessions = Mock(side_effect=[[{"State": 0, "SessionId": 2}], [{"State": 4, "SessionId": 2}]])
    monkeypatch.setattr(ts, "WTSEnumerateSessions", enumerate_sessions)
    state["info"]["state"] = 4
    result = safety.sessions()
    assert result == {"healthy": True, "sessions": []}
    assert enumerate_sessions.call_count == 2 and len(state["retry_clock"].sleeps) == 1


def test_user_token_not_yet_available_is_retried(nat_adapter, monkeypatch):
    safety, state = nat_adapter
    token = Mock()
    query = Mock(side_effect=[OSError("User token is not available yet"), token])
    monkeypatch.setattr(sys.modules["win32ts"], "WTSQueryUserToken", query)
    assert safety.sessions()["healthy"]
    assert query.call_count == 2 and len(state["retry_clock"].sleeps) == 1
    token.Close.assert_called_once()


def test_persistent_missing_current_event_still_rolls_back_within_retry_budget(guard, pending_nat_activation):
    state = pending_nat_activation
    state["xml"] = source_xml(timestamp=NOW - 1)
    with pytest.raises(RuntimeError, match="current connection"):
        guard.tick(force=True)
    assert state["retry_clock"].now == pytest.approx(SESSION_RETRY_SECONDS)
    assert len(state["retry_clock"].sleeps) <= 21
    assert guard.mode == "MONITOR ONLY"
    guard.tick(force=True)
    assert not guard.lease_path.exists() and not guard.firewall.backend.list_rules()
    with pytest.raises(ValueError, match="No pending activation"):
        guard.confirm_active("test")


def test_slow_native_read_uses_up_retry_budget_without_another_attempt(nat_adapter):
    safety, state = nat_adapter
    retry_clock = state["retry_clock"]

    def slow_read(session_id):
        retry_clock.now += SESSION_RETRY_SECONDS + 0.1
        return source_xml(timestamp=NOW - 10)

    read_event = Mock(side_effect=slow_read)
    safety._sources.read_event = read_event
    assert not safety.sessions()["healthy"]
    read_event.assert_called_once()
    assert not retry_clock.sleeps


def test_retry_cannot_extend_activation_deadline(guard, pending_nat_activation):
    state = pending_nat_activation
    guard.clock.now = NOW + 179.95
    state.update(info=clock_info(connected=NOW + 179, current=NOW + 180), xml=source_xml(), now=NOW + 180)

    def publish_after_deadline():
        guard.clock.now = NOW + 180.05
        state["xml"] = source_xml(timestamp=NOW + 179.003)

    state["retry_clock"].on_sleep = publish_after_deadline
    with pytest.raises(ValueError, match="expired"):
        guard.confirm_active("test")
    assert not json.loads(guard.lease_path.read_text())["confirmed"]
