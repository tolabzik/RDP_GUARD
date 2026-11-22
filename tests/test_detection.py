import json

import pytest

from conftest import activate, event_xml, failures
from rdp_guard.events import SECURITY, parse_event
from rdp_guard.guard import Guard


def blocks(guard):
    return guard.store.rows("SELECT * FROM blocks WHERE ended IS NULL")


def test_one_failure_is_not_a_block(guard):
    activate(guard)
    failures(guard, 1)
    assert blocks(guard) == []
    assert guard.firewall.backend.changes == 0


def test_threshold_creates_verified_scoped_block(guard):
    activate(guard)
    failures(guard)
    block = blocks(guard)[0]
    assert block["status"] == "applied" and block["attempts"] == 10
    assert block["expires"] - block["created"] == 3600
    rules = guard.firewall.backend.list_rules()
    assert {r.protocol for r in rules} == {6, 17}
    assert all(r.port == 33345 and r.addresses == ("198.51.100.7/32",) for r in rules)


def test_type_three_is_unconfirmed_and_disabled_by_default(guard):
    event = parse_event(event_xml(logon_type=3))
    assert event.category == "Network-auth" and event.confidence == "unconfirmed"
    activate(guard)
    failures(guard, logon_type=3)
    assert not blocks(guard)


def test_opt_in_network_auth_only_blocks_rdp(guard):
    guard.dispatch("update-settings", {"settings": {"include_network_auth": True}}, "test")
    activate(guard)
    failures(guard, logon_type=3)
    assert all(r.port == 33345 for r in guard.firewall.backend.list_rules())
    assert len(blocks(guard)) == 1


def test_duplicate_record_not_counted_twice(guard):
    activate(guard)
    for _ in range(15):
        guard.ingest(event_xml(timestamp=guard.clock()), SECURITY, "same")
    assert len(guard.store.rows("SELECT * FROM events")) == 1
    assert not blocks(guard)


def test_record_id_reuse_after_log_clear_is_new_event(guard):
    guard.ingest(event_xml(timestamp=guard.clock()), SECURITY, "first")
    guard.clock.now += 1
    guard.ingest(event_xml(timestamp=guard.clock()), SECURITY, "second")
    assert len(guard.store.rows("SELECT * FROM events")) == 2


def test_whitelist_protects_ipv4_mapped_address(guard):
    activate(guard)
    guard.dispatch("whitelist-add", {"network": "198.51.100.0/24"}, "test")
    failures(guard, ip="::ffff:198.51.100.7")
    assert not blocks(guard)
    assert {e["disposition"] for e in guard.store.rows("SELECT * FROM events")} == {"whitelisted"}


def test_active_admin_session_cannot_be_blocked(guard):
    failures(guard, ip="203.0.113.10")
    assert not blocks(guard)
    assert guard.store.rows("SELECT * FROM audit WHERE action='admin-ip-attempt'")
    with pytest.raises(ValueError, match="administrative"):
        guard.dispatch("block", {"network": "203.0.113.0/24"}, "test")


def test_unknown_session_inventory_inhibits_detection(guard):
    guard.safety.ok = False
    failures(guard)
    assert not blocks(guard)


def test_ttl_expiry_and_repeat_escalation(guard):
    activate(guard)
    failures(guard)
    lease = json.loads(guard.lease_path.read_text())
    lease["deadline"] = None
    guard.lease_path.write_text(json.dumps(lease))
    guard.clock.now += 3601
    guard.tick(force=True)
    assert not blocks(guard) and not guard.firewall.backend.list_rules()
    guard.clock.now += 1
    failures(guard, start=20)
    block = blocks(guard)[0]
    assert block["strikes"] == 2 and block["expires"] - block["created"] == 86400
    assert block["kind"] == "dynamic"


def test_monitor_only_records_proposals_without_firewall_changes(guard):
    failures(guard)
    assert blocks(guard)[0]["status"] == "proposed"
    assert guard.firewall.backend.changes == 0
    assert not guard.store.rows("SELECT * FROM strikes")


def test_restart_retains_decision_and_deduplicates(guard):
    activate(guard)
    failures(guard)
    restarted = Guard(guard.store, guard.firewall.backend, guard.safety, guard.data_dir, guard.clock)
    restarted.ingest(event_xml(timestamp=guard.clock()), SECURITY, "replayed")
    restarted.tick(force=True)
    assert len(blocks(restarted)) == 1
    assert len(guard.store.rows("SELECT * FROM events")) == 10
    assert restarted.store.rows("SELECT xml FROM bookmarks")[0]["xml"] == "replayed"


@pytest.mark.parametrize("ip", ["2001:db8::8", "::ffff:198.51.100.8", "198.51.100.8"])
def test_supported_source_addresses(guard, ip):
    activate(guard)
    failures(guard, ip=ip)
    assert blocks(guard)[0]["status"] == "applied"


@pytest.mark.parametrize("ip", ["-", "", "garbage", "127.0.0.1", "::1", "0.0.0.0", "::", "224.1.1.1"])
def test_invalid_and_protected_sources_never_block(guard, ip):
    failures(guard, ip=ip)
    assert not blocks(guard)


def test_malformed_events_advance_bookmark_without_blocking(guard):
    guard.ingest("<invalid", SECURITY, "after-bad-event")
    assert not blocks(guard)
    assert guard.store.rows("SELECT xml FROM bookmarks")[0]["xml"] == "after-bad-event"
    assert guard.store.rows("SELECT * FROM audit WHERE action='parse-rejected'")


def test_decision_and_bookmark_rollback_together(guard, monkeypatch):
    def broken(*args):
        raise RuntimeError("Simulated failure before commit")
    monkeypatch.setattr(guard, "_detect", broken)
    with pytest.raises(RuntimeError):
        guard.ingest(event_xml(), SECURITY, "never-saved")
    assert not guard.store.rows("SELECT * FROM events")
    assert not guard.store.rows("SELECT * FROM bookmarks")


def test_old_events_do_not_create_new_bans(guard):
    activate(guard)
    for i in range(20):
        guard.ingest(event_xml(record=i, timestamp=guard.clock() - 3600), SECURITY, str(i))
    assert not blocks(guard)


def test_whitelist_add_removes_entire_overlapping_manual_block(guard):
    activate(guard)
    guard.dispatch("block", {"network": "198.51.100.0/24"}, "test")
    guard.dispatch("whitelist-add", {"network": "198.51.100.7"}, "test")
    assert not blocks(guard)
    assert not guard.firewall.backend.list_rules()


def test_permanent_blocks_are_not_expired(guard):
    guard.dispatch("block", {"network": "198.51.100.7"}, "test")
    guard.clock.now += 9999999
    guard.tick(force=True)
    assert blocks(guard)[0]["kind"] == "static"


def test_mass_false_positive_circuit_breaker(guard):
    guard.dispatch("update-settings", {"settings": {"max_blocks_per_minute": 1}}, "test")
    activate(guard)
    failures(guard)
    failures(guard, start=20, ip="198.51.100.8")
    assert guard.mode == "MONITOR ONLY"
    assert not guard.firewall.backend.list_rules()


def test_firewall_failure_is_not_reported_as_applied(guard, monkeypatch):
    activate(guard)
    def broken(rule):
        raise RuntimeError("COM failure")
    monkeypatch.setattr(guard.firewall.backend, "add", broken)
    with pytest.raises(RuntimeError, match="COM failure"):
        failures(guard)
    assert blocks(guard)[0]["status"] == "error"
    assert guard.mode == "MONITOR ONLY"


def test_live_session_appearing_after_decision_is_protected(guard):
    activate(guard)
    failures(guard)
    guard.safety.admin_sessions.append({"id": 3, "ip": "198.51.100.7", "username": "admin"})
    guard.tick(force=True)
    assert blocks(guard)[0]["status"] == "protected"
    assert not guard.firewall.backend.list_rules()
