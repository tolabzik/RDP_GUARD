"""RdpCoreTS/140 uses its own native IPString, without guessing a Security identity."""
from datetime import datetime, timezone
import json
from xml.sax.saxutils import escape

import pytest

from conftest import activate, event_xml, failures
from rdp_guard.events import RDP_CORE, SECURITY, parse_event
from rdp_guard.guard import Guard


def core_xml(record=1, timestamp=1_800_000_000, ip="198.51.100.7", event_id=140):
    # Same schema as the native Server 2012 R2 event supplied during investigation.
    # Addresses, record IDs and timestamps here are synthetic test values.
    date = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><Provider Name="Microsoft-Windows-RemoteDesktopServices-RdpCoreTS"
    Guid="{{1139C61B-B549-4251-8ED3-27250A1EDEC8}}"/>
    <EventID>{event_id}</EventID><Version>0</Version><Level>3</Level><Task>4</Task><Opcode>14</Opcode>
    <Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime="{date}"/>
    <EventRecordID>{record}</EventRecordID><Correlation ActivityID="{{00000000-0000-0000-0000-000000000001}}"/>
    <Execution ProcessID="3284" ThreadID="7736"/><Channel>{RDP_CORE}</Channel>
    <Computer>TEST-SERVER</Computer><Security UserID="S-1-5-20"/></System>
    <EventData><Data Name="IPString">{escape(ip)}</Data></EventData></Event>'''


def core_failures(guard, count=10, start=1, **kwargs):
    for record in range(start, start + count):
        guard.ingest(core_xml(record=record, timestamp=guard.clock(), **kwargs), RDP_CORE, f"core-{record}")
    guard.tick(force=True)


def blocks(guard):
    return guard.dispatch("list-blocks", {}, "test")


def test_native_schema_is_rdp_failure_without_invented_account():
    event = parse_event(core_xml())
    assert (event.channel, event.event_id, event.ip) == (RDP_CORE, 140, "198.51.100.7")
    assert (event.category, event.confidence) == ("RDP-confirmed", "high")
    assert event.username == event.domain == event.status == event.substatus == ""
    assert event.logon_type is event.source_port is None
    assert "incorrect username or password" in event.reason


@pytest.mark.parametrize("ip,net", [("198.51.100.7", "198.51.100.7/32"),
                                   ("::ffff:198.51.100.7", "198.51.100.7/32"),
                                   ("2001:db8::7", "2001:db8::7/128")])
def test_140_threshold_applies_only_rdp_rules_without_network_auth_opt_in(guard, ip, net):
    activate(guard)
    assert not guard.settings.include_network_auth
    core_failures(guard, count=9, ip=ip)
    assert not blocks(guard) and not guard.firewall.backend.list_rules()
    core_failures(guard, count=1, start=10, ip=ip)
    block, = blocks(guard)
    assert block["status"] == "applied" and block["attempts"] == 10
    assert block["strikes"] == 1 and block["expires"] - block["created"] == 3600
    assert RDP_CORE in block["reason"] and "140" in block["reason"]
    rules = guard.firewall.backend.list_rules()
    assert {r.protocol for r in rules} == {6, 17}
    assert all(r.port == 33345 and r.addresses == (net,) for r in rules)


@pytest.mark.parametrize("security_first", [True, False])
@pytest.mark.parametrize("logon_type", [3, 10])
def test_two_sources_never_combine_toward_threshold_or_escalate_twice(guard, security_first, logon_type):
    guard.dispatch("update-settings", {"settings": {"include_network_auth": True}}, "test")
    activate(guard)
    for record in range(1, 11):
        pair = [(event_xml(record=record, logon_type=logon_type), SECURITY), (core_xml(record=record), RDP_CORE)]
        if not security_first:
            pair.reverse()
        for xml, channel in pair:
            guard.ingest(xml, channel, f"record-{record}")
        guard.tick(force=True)
        if record < 10:
            assert not blocks(guard)  # 18 records still represent only 9 failures per source.
    block, = blocks(guard)
    assert block["attempts"] == 10 and block["strikes"] == 1
    assert guard.store.rows("SELECT count FROM strikes") == [{"count": 1}]
    assert len(guard.store.rows("SELECT * FROM audit WHERE action='block-decision'")) == 1


def test_missing_security_ip_does_not_hide_core_failures_or_inherit_account(guard):
    activate(guard)
    for record in range(1, 11):
        guard.ingest(event_xml(record=record, ip="-", logon_type=3, username="ADMINISTRATEUR"), SECURITY, str(record))
        guard.ingest(core_xml(record=record), RDP_CORE, str(record))
    guard.tick(force=True)
    assert blocks(guard)[0]["status"] == "applied"
    security = guard.store.rows("SELECT ip,disposition FROM events WHERE channel=?", (SECURITY,))
    assert all(e == {"ip": None, "disposition": "no-source-ip"} for e in security)
    assert all(e["username"] == "" for e in guard.store.rows("SELECT username FROM events WHERE channel=?", (RDP_CORE,)))
    snapshot = guard.snapshot()
    assert snapshot["counters"]["minute"] == {"n": 20, "unique_ips": 1, "with_ip": 10}
    assert sum(h["count"] for h in snapshot["histogram"]) == 20
    sources = {s["channel"]: s for s in snapshot["failure_sources"]}
    assert sources[RDP_CORE] == {"channel": RDP_CORE, "event_id": 140, "n": 10, "with_ip": 10}
    assert sources[SECURITY]["n"] == 10 and sources[SECURITY]["with_ip"] == 0


@pytest.mark.parametrize("change", [
    lambda x: x.replace('Name="Microsoft-Windows-RemoteDesktopServices-RdpCoreTS"', 'Name="Other-Provider"'),
    lambda x: x.replace(f"<Channel>{RDP_CORE}</Channel>", "<Channel>Security</Channel>"),
    lambda x: x.replace("<EventID>140</EventID>", "<EventID>131</EventID>"),
    lambda x: x.replace("<EventID>140</EventID>", "<EventID>4625</EventID>"),
])
def test_connection_only_or_wrong_provider_is_not_a_failure(guard, change):
    with pytest.raises(ValueError):
        parse_event(change(core_xml()))
    assert not guard.ingest(change(core_xml()), RDP_CORE, "after-rejected")
    assert not guard.store.rows("SELECT * FROM events") and not blocks(guard)
    assert guard.store.rows("SELECT xml FROM bookmarks WHERE channel=?", (RDP_CORE,)) == [{"xml": "after-rejected"}]


@pytest.mark.parametrize("ip", ["-", "", "invalid", "127.0.0.1", "::1", "0.0.0.0", "::", "224.1.1.1", "fe80::1%1"])
def test_missing_or_protected_ip_is_visible_but_never_blocked(guard, ip):
    core_failures(guard, ip=ip)
    assert not blocks(guard)
    assert {e["disposition"] for e in guard.store.rows("SELECT disposition FROM events")} == {"no-source-ip"}
    assert guard.snapshot()["counters"]["minute"] == {"n": 10, "unique_ips": 0, "with_ip": 0}


def test_missing_ipstring_never_falls_back_to_another_field():
    event = parse_event(core_xml().replace('Name="IPString"', 'Name="IpAddress"'))
    assert event.ip is None
    security = parse_event(event_xml(ip="-").replace("</EventData>", '<Data Name="IPString">198.51.100.7</Data></EventData>'))
    assert security.ip is None


@pytest.mark.parametrize("protection", ["whitelist", "session", "unavailable"])
def test_core_failures_respect_trust_and_session_inventory(guard, protection):
    activate(guard)
    if protection == "whitelist":
        guard.dispatch("whitelist-add", {"network": "198.51.100.7"}, "test")
    elif protection == "session":
        guard.safety.admin_sessions.append({"id": 3, "ip": "198.51.100.7", "username": "admin"})
    else:
        guard.safety.ok = False
    for record in range(10):
        guard.ingest(core_xml(record=record), RDP_CORE, str(record))
    assert not blocks(guard) and not guard.firewall.backend.list_rules()
    expected = {"whitelist": "whitelisted", "session": "admin-protected", "unavailable": "safety-unavailable"}
    assert {e["disposition"] for e in guard.store.rows("SELECT disposition FROM events")} == {expected[protection]}


def test_core_bookmark_replay_restart_and_record_reuse(guard):
    for _ in range(12):
        guard.ingest(core_xml(), RDP_CORE, "same-record")
    restarted = Guard(guard.store, guard.firewall.backend, guard.safety, guard.data_dir, guard.clock)
    assert not restarted.ingest(core_xml(), RDP_CORE, "replayed")
    assert guard.store.rows("SELECT xml FROM bookmarks WHERE channel=?", (RDP_CORE,)) == [{"xml": "replayed"}]
    assert len(guard.store.rows("SELECT * FROM events")) == 1 and not blocks(guard)
    guard.clock.now += 1
    assert restarted.ingest(core_xml(timestamp=guard.clock()), RDP_CORE, "after-clear")
    assert len(guard.store.rows("SELECT * FROM events")) == 2


def test_old_core_history_does_not_read_live_sessions_or_block(guard, monkeypatch):
    activate(guard)
    def unavailable():
        raise AssertionError("Old records must not enumerate live sessions")
    monkeypatch.setattr(guard, "protected", unavailable)
    for record in range(20):
        guard.ingest(core_xml(record=record, timestamp=guard.clock() - 3600), RDP_CORE, str(record))
    assert not blocks(guard)
    assert {e["disposition"] for e in guard.store.rows("SELECT disposition FROM events")} == {"historical"}


def test_monitor_proposal_is_not_an_applied_block(guard):
    core_failures(guard)
    assert blocks(guard)[0]["status"] == "proposed"
    assert not guard.firewall.backend.list_rules() and not guard.store.rows("SELECT * FROM strikes")
    activate(guard)
    assert not blocks(guard)  # Activation discards Monitor Only proposals.


def test_core_threshold_is_per_ip_and_window(guard):
    activate(guard)
    core_failures(guard, count=9)
    core_failures(guard, count=9, start=20, ip="198.51.100.8")
    assert not blocks(guard)
    # Keep the activation lease confirmed while advancing the detection window.
    lease = json.loads(guard.lease_path.read_text())
    lease["deadline"] = None
    guard.lease_path.write_text(json.dumps(lease))
    guard.clock.now += guard.settings.window_seconds + 1
    core_failures(guard, count=1, start=40)
    assert not blocks(guard)
    assert guard.snapshot()["counters"]["minute"]["n"] == 1
    assert guard.snapshot()["counters"]["hour"]["n"] == 19


def test_core_unblock_does_not_reban_using_other_source_old_evidence(guard):
    activate(guard)
    failures(guard, count=9)
    core_failures(guard)
    assert blocks(guard)[0]["status"] == "applied"
    guard.clock.now += 1
    guard.dispatch("unblock", {"network": "198.51.100.7"}, "test")
    guard.clock.now += 1
    failures(guard, count=1, start=20)
    core_failures(guard, count=1, start=20)
    assert not blocks(guard)


def test_core_expiry_escalates_only_after_fresh_threshold(guard):
    activate(guard)
    core_failures(guard)
    lease = json.loads(guard.lease_path.read_text())
    lease["deadline"] = None
    guard.lease_path.write_text(json.dumps(lease))
    guard.clock.now += 3601
    guard.tick(force=True)
    assert not blocks(guard) and not guard.firewall.backend.list_rules()
    guard.clock.now += 1
    core_failures(guard, start=20)
    block, = blocks(guard)
    assert block["strikes"] == 2 and block["expires"] - block["created"] == 86400


def test_success_and_context_do_not_pollute_failure_counters(guard):
    guard.ingest(event_xml(event_id=4624), SECURITY, "success")
    guard.ingest(event_xml(record=2, event_id=4778), SECURITY, "context")
    guard.ingest(core_xml(timestamp=guard.clock() + 60), RDP_CORE, "future")
    assert guard.snapshot()["counters"]["day"]["n"] == 0
    assert not blocks(guard)
