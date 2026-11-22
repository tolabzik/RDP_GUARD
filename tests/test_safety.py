from dataclasses import replace
import json

import pytest

from conftest import activate, event_xml, failures
from rdp_guard.events import RCM, SECURITY, parse_event
from rdp_guard.firewall import FirewallEngine, MemoryFirewall, Rule, plan_rules
from rdp_guard.models import Settings, network


@pytest.mark.parametrize("value", ["*", "0.0.0.0/0", "::/0", "192.0.2.0/16", "127.0.0.0/8", "::/64", "224.0.0.0/4", "198.51.100.3/24", "LocalSubnet", "192.0.2.1,198.51.100.1"])
def test_unsafe_networks_rejected(value):
    with pytest.raises(ValueError):
        network(value, blocking=True)


def test_empty_list_never_creates_wildcard_rule():
    assert plan_rules([], 33345) == []


def test_batch_limit_and_both_protocols():
    rules = plan_rules([f"198.51.{i // 254}.{i % 254 + 1}" for i in range(401)], 33345)
    assert len(rules) == 6
    assert max(len(r.addresses) for r in rules) == 200


def test_emergency_removes_only_owned_rules(guard):
    activate(guard)
    failures(guard)
    foreign = Rule("Existing RDP allow", 6, 33345, ("*",), group="Windows", description="Existing", action=1)
    guard.firewall.backend.rules[foreign.name] = foreign
    guard.dispatch("emergency-disable", {}, "test")
    assert guard.firewall.backend.list_rules() == [foreign]
    assert guard.emergency_path.exists()
    assert guard.mode == "MONITOR ONLY"


def test_ownership_collision_is_not_overwritten():
    backend = MemoryFirewall()
    foreign = replace(plan_rules(["198.51.100.7"], 33345)[0], description="Not RDP Guard")
    backend.rules[foreign.name] = foreign
    with pytest.raises(RuntimeError, match="foreign"):
        FirewallEngine(backend).reconcile(["198.51.100.8"], 33345)
    assert backend.rules[foreign.name] == foreign


def test_firewall_readback_mismatch_raises():
    class DropFirewall(MemoryFirewall):
        def add(self, rule):
            pass
    with pytest.raises(RuntimeError, match="read-back"):
        FirewallEngine(DropFirewall()).reconcile(["198.51.100.7"], 33345)


def test_activation_requires_admin_whitelist_backup_and_checks(guard):
    with pytest.raises(ValueError, match="Preflight"):
        guard.dispatch("activate", {"confirmation": "ENABLE RDP GUARD", "backup_access": True}, "test")
    guard.dispatch("whitelist-add", {"network": "203.0.113.10"}, "test")
    with pytest.raises(ValueError, match="confirmation"):
        guard.dispatch("activate", {}, "test")
    guard.safety.checks["watchdog"] = False
    with pytest.raises(ValueError, match="independent_watchdog"):
        guard.dispatch("activate", {"confirmation": "ENABLE RDP GUARD", "backup_access": True}, "test")


def test_unconfirmed_activation_rolls_back(guard):
    activate(guard)
    failures(guard)
    guard.clock.now += 181
    guard.tick(force=True)
    assert guard.mode == "MONITOR ONLY"
    assert not guard.firewall.backend.list_rules()
    assert guard.emergency_path.exists()


def test_confirm_requires_new_real_logon_and_not_1149(guard):
    activate(guard)
    with pytest.raises(ValueError, match="not been observed"):
        guard.dispatch("confirm-active", {}, "test")
    guard.clock.now += 10
    context = event_xml(record=5, timestamp=guard.clock(), ip="203.0.113.10", username="administrator", event_id=1149,
                        channel=RCM, provider="Microsoft-Windows-TerminalServices-RemoteConnectionManager")
    assert parse_event(context).category == "RDP-context"
    guard.ingest(context, RCM, "context-bookmark")
    with pytest.raises(ValueError):
        guard.dispatch("confirm-active", {}, "test")
    guard.ingest(event_xml(record=6, timestamp=guard.clock(), ip="203.0.113.10", username="administrator", event_id=4624), SECURITY, "proof")
    assert guard.dispatch("confirm-active", {}, "test")["confirmed"]
    assert json.loads(guard.lease_path.read_text())["deadline"] is None


def test_missing_lease_inhibits_protection(guard):
    activate(guard)
    guard.lease_path.unlink()
    with pytest.raises(RuntimeError, match="missing"):
        guard.tick(force=True)
    assert guard.mode == "MONITOR ONLY"


def test_reactivation_does_not_apply_monitor_proposals(guard):
    failures(guard)
    activate(guard)
    assert not guard.firewall.backend.list_rules()
    assert not guard.store.rows("SELECT * FROM blocks WHERE ended IS NULL")


def test_whitelist_blacklist_overlap_rejected(guard):
    guard.dispatch("whitelist-add", {"network": "198.51.100.7"}, "test")
    with pytest.raises(ValueError, match="whitelist"):
        guard.dispatch("block", {"network": "198.51.100.0/24"}, "test")


def test_bad_import_is_atomic(guard):
    with pytest.raises(ValueError):
        guard.dispatch("import-lists", {"kind": "whitelist", "entries": [{"network": "198.51.100.7"}, {"network": "*"}]}, "test")
    assert not guard.store.rows("SELECT * FROM whitelist")


@pytest.mark.parametrize("settings", [{"threshold": 0}, {"threshold": True}, {"rdp_port": 65536}, {"unknown": 1},
                                     {"ban_seconds": []}, {"ban_seconds": [3600, 60]}, {"include_network_auth": "false"}])
def test_bad_settings_rejected(settings):
    with pytest.raises(ValueError):
        Settings.load(settings)


def test_do_not_reinterpret_other_logon_types_as_network_rdp():
    assert parse_event(event_xml(logon_type=2)).category == "Other"


def test_untrusted_xml_provider_and_entities_rejected():
    with pytest.raises(ValueError):
        parse_event(event_xml(provider="Untrusted"))
    with pytest.raises(Exception):
        parse_event('<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>')
