"""Portable planner/executor contract tests; these do not validate a Linux hook."""
from dataclasses import replace
import copy
import ipaddress
import json
import re
import subprocess

import pytest

from rdp_guard.proxy_firewall import (
    ProxyBan, ProxyFirewallConfig, ProxyFirewallError, ScopedNftFirewall, build_plan,
)


def config(**kwargs):
    return ProxyFirewallConfig("stream-one", "192.0.2.10", 45451, **kwargs)


def native_objects(settings, ips=()):
    common = {"family": "inet", "table": settings.table_name, "comment": settings.ownership_marker}
    result = [{"table": {"family": "inet", "name": settings.table_name,
                         "comment": settings.ownership_marker}}]
    for version in (4, 6):
        for prefix, flags in (("banned", ["timeout"]), ("trusted", ["interval"])):
            item = {**common, "name": f"{prefix}{version}", "type": f"ipv{version}_addr", "flags": flags}
            if prefix == "banned":
                item["elem"] = [{"elem": {"val": ip, "timeout": 30, "expires": 29}} for ip in ips
                                if ipaddress.ip_address(ip).version == version]
            result.append({"set": item})
    result.append({"chain": {**common, "name": "ingress", "type": "filter", "hook": "prerouting",
                             "prio": -150, "policy": "accept"}})
    version = ipaddress.ip_address(settings.listener_ip).version
    family = "ip" if version == 4 else "ip6"
    for protocol in settings.protocols:
        for verdict, prefix in (("return", "trusted"), ("drop", "banned")):
            expressions = [{"match": {"op": "==", "left": {"payload": {"protocol": p, "field": f}},
                                      "right": value}} for p, f, value in
                           ((family, "daddr", settings.listener_ip), (protocol, "dport", settings.listener_port),
                            (family, "saddr", f"@{prefix}{version}"))]
            if verdict == "drop":
                expressions.append({"counter": {"packets": 0, "bytes": 0}})
            expressions.append({verdict: None})
            result.append({"rule": {**common, "chain": "ingress", "expr": expressions}})
    return result


class FakeNft:
    """Small command boundary fake, not a simulated packet filter."""
    def __init__(self, settings):
        self.settings, self.objects, self.calls = settings, None, []
        self.reject_check = False
        self.lose_readback = False

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        assert kwargs["timeout"] == 10 and kwargs["check"] is False
        assert kwargs.get("shell") is None
        output = ""
        if args[1:] == ["-j", "list", "tables"]:
            output = json.dumps({"nftables": [self.objects[0]] if self.objects else []})
        elif args[1:4] == ["-j", "list", "table"]:
            output = json.dumps({"nftables": self.objects})
        elif args[1:] == ["-c", "-f", "-"]:
            if self.reject_check:
                return subprocess.CompletedProcess(args, 1, "", "syntax invalid")
        elif args[1:] == ["-f", "-"]:
            script = kwargs["input"]
            if script.startswith("delete table"):
                self.objects = None
            else:
                ips = re.findall(r"([0-9a-f.:]+) timeout \d+s", script)
                self.objects = native_objects(self.settings, [] if self.lose_readback else ips)
        else:
            raise AssertionError(args)
        return subprocess.CompletedProcess(args, 0, output, "")


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr("rdp_guard.proxy_firewall.sys.platform", "linux")


def test_scoped_prednat_tcp_only_no_shared_chain_mutation():
    plan = build_plan(config(), [ProxyBan("198.51.100.8", 120)], now=100)
    assert "type filter hook prerouting priority -150; policy accept;" in plan.script
    assert "ip daddr 192.0.2.10 tcp dport 45451 ip saddr @banned4 counter drop" in plan.script
    assert "198.51.100.8 timeout 20s" in plan.script
    assert "udp dport" not in plan.script
    assert "DOCKER" not in plan.script and "flush ruleset" not in plan.script
    assert "hook input" not in plan.script and "hook forward" not in plan.script
    assert plan.script.startswith("create table inet rdpg_proxy_")


def test_ipv6_and_explicit_udp_are_separate_and_scoped():
    settings = replace(config(), listener_ip="2001:db8::10", protocols=("udp", "tcp"))
    plan = build_plan(settings, [ProxyBan("2001:db8::20", 120)], now=100)
    assert "type ipv4_addr" in plan.script and "type ipv6_addr" in plan.script
    assert "ip6 daddr 2001:db8::10 udp dport 45451 ip6 saddr @banned6" in plan.script
    assert "ip6 daddr 2001:db8::10 tcp dport 45451 ip6 saddr @banned6" in plan.script
    assert "banned6 { 2001:db8::20 timeout 20s }" in plan.script
    assert "banned4 { 2001" not in plan.script


@pytest.mark.parametrize("ip", ["0.0.0.0", "::", "127.0.0.1", "::1", "224.0.0.1", "ff02::1",
                               "255.255.255.255", "198.51.100.1/32", "198.51.100.1; flush ruleset",
                               "::ffff:192.0.2.1"])
def test_no_wildcard_network_or_injected_listener(ip):
    with pytest.raises(ValueError):
        replace(config(), listener_ip=ip)


@pytest.mark.parametrize("ip", ["0.0.0.0/0", "198.51.100.0/24", "::/0", "*", "198.51.100.1\ndrop"])
def test_bans_are_literal_single_clients_only(ip):
    with pytest.raises(ValueError):
        build_plan(config(), [ProxyBan(ip, 120)], now=100)


def test_wrong_address_family_is_not_silently_installed():
    with pytest.raises(ValueError, match="families"):
        build_plan(config(), [ProxyBan("2001:db8::1", 120)], now=100)


def test_empty_and_whitelisted_addresses_never_expand_scope():
    settings = config(whitelist=("198.51.100.0/24", "198.51.100.5/32"))
    plan = build_plan(settings, [ProxyBan("198.51.100.5", 120)], now=100)
    assert plan.bans == () and plan.whitelisted == ("198.51.100.5",)
    assert "elements = { 198.51.100.0/24 }" in plan.script
    assert "add element" not in plan.script
    assert "saddr @trusted4 return" in plan.script
    assert build_plan(config(), [], now=100).bans == ()


def test_finite_absolute_expiry_does_not_refresh_on_sync():
    settings = config(max_ttl_seconds=30)
    ban = ProxyBan("198.51.100.5", 130)
    assert "timeout 30s" in build_plan(settings, [ban], now=100).script
    assert "timeout 19s" in build_plan(settings, [ban], now=110.8).script
    assert build_plan(settings, [ban], now=130).bans == ()
    with pytest.raises(ValueError, match="maximum TTL"):
        build_plan(settings, [ProxyBan(ban.client_ip, 131)], now=100)
    for expiry in (float("inf"), float("nan"), True):
        with pytest.raises(ValueError):
            build_plan(settings, [ProxyBan(ban.client_ip, expiry)], now=100)


def test_entry_count_and_duplicate_rejected_before_commands():
    with pytest.raises(ValueError, match="entry limit"):
        build_plan(config(max_entries=1), [ProxyBan("198.51.100.1", 120),
                                          ProxyBan("198.51.100.2", 120)], now=100)
    with pytest.raises(ValueError, match="Duplicate"):
        build_plan(config(), [ProxyBan("198.51.100.1", 120)] * 2, now=100)


def test_updates_replace_only_owned_ban_sets_preserving_rule_counters():
    plan = build_plan(config(), [], now=100, table_exists=True)
    assert plan.script == (f"flush set inet {config().table_name} banned4\n"
                           f"flush set inet {config().table_name} banned6\n")
    assert "delete" not in plan.script and "add chain" not in plan.script


def test_ownership_tracks_immutable_scope_and_whitelist():
    original = config()
    other = replace(original, listener_port=45452)
    assert original.table_name == other.table_name
    assert original.ownership_marker != other.ownership_marker
    assert original.ownership_marker != replace(original, whitelist=("192.0.2.1/32",)).ownership_marker
    assert original.table_name != replace(original, stream_id="different-stream").table_name


def test_monitor_does_not_even_read_firewall():
    fake = FakeNft(config())
    firewall = ScopedNftFirewall(config(), runner=fake)
    assert firewall.sync([ProxyBan("198.51.100.1", 120)], now=100).reason == "monitor_only"
    assert firewall.remove().reason == "monitor_only"
    assert fake.calls == []


def test_enforcement_requires_local_approval_and_linux(linux, monkeypatch):
    fake = FakeNft(config())
    with pytest.raises(ProxyFirewallError, match="local approval"):
        ScopedNftFirewall(config(), runner=fake).sync([], mode="enforce", now=100)
    monkeypatch.setattr("rdp_guard.proxy_firewall.sys.platform", "darwin")
    with pytest.raises(ProxyFirewallError, match="requires Linux"):
        ScopedNftFirewall(config(enforcement_approved=True), runner=fake).sync([], mode="enforce", now=100)
    assert fake.calls == []


def test_sync_check_apply_verify_and_manual_unblock(linux):
    settings = config(enforcement_approved=True)
    fake = FakeNft(settings)
    firewall = ScopedNftFirewall(settings, runner=fake, monotonic=lambda: 100)
    assert firewall.sync([ProxyBan("198.51.100.2", 130)], mode="enforce", now=100).applied
    # Removal bypasses throttle, but is still scoped and ownership-checked.
    assert firewall.sync([], mode="enforce", now=100).applied
    commands = [args[1:] for args, _ in fake.calls]
    assert commands.index(["-c", "-f", "-"]) < commands.index(["-f", "-"])
    mutations = [kw["input"] for args, kw in fake.calls if args[1:] == ["-f", "-"]]
    assert "create table" in mutations[0] and mutations[1].startswith("flush set")


@pytest.mark.parametrize("mutation", ["table_owner", "extra_chain", "hook", "set_type", "rule_owner",
                                      "missing_destination", "wrong_port", "wrong_verdict"])
def test_foreign_or_modified_table_is_never_overwritten_or_removed(linux, mutation):
    settings = config(enforcement_approved=True)
    fake = FakeNft(settings)
    fake.objects = native_objects(settings)
    if mutation == "table_owner":
        fake.objects[0]["table"]["comment"] = "another application"
    elif mutation == "extra_chain":
        fake.objects.append(copy.deepcopy(fake.objects[5]))
    elif mutation == "hook":
        fake.objects[5]["chain"]["hook"] = "input"
    elif mutation == "set_type":
        fake.objects[1]["set"]["type"] = "ipv6_addr"
    elif mutation == "rule_owner":
        fake.objects[-1]["rule"]["comment"] = "foreign rule"
    elif mutation == "missing_destination":
        del fake.objects[-1]["rule"]["expr"][0]
    elif mutation == "wrong_port":
        fake.objects[-1]["rule"]["expr"][1]["match"]["right"] = 22
    elif mutation == "wrong_verdict":
        fake.objects[-1]["rule"]["expr"][-1] = {"accept": None}
    firewall = ScopedNftFirewall(settings, runner=fake)
    with pytest.raises(ProxyFirewallError):
        firewall.sync([], mode="enforce", now=100)
    with pytest.raises(ProxyFirewallError):
        firewall.remove(mode="enforce")
    assert all("-f" not in args for args, _ in fake.calls)


def test_check_failure_never_executes_mutation(linux):
    settings = config(enforcement_approved=True)
    fake = FakeNft(settings)
    fake.reject_check = True
    with pytest.raises(ProxyFirewallError, match="rejected"):
        ScopedNftFirewall(settings, runner=fake).sync([], mode="enforce", now=100)
    assert not any(args[1:] == ["-f", "-"] for args, _ in fake.calls)


def test_bad_readback_is_not_reported_applied(linux):
    settings = config(enforcement_approved=True)
    fake = FakeNft(settings)
    fake.lose_readback = True
    with pytest.raises(ProxyFirewallError, match="read-back"):
        ScopedNftFirewall(settings, runner=fake).sync([ProxyBan("198.51.100.1", 130)],
                                                    mode="enforce", now=100)


def test_failed_readback_attempts_still_consume_new_ban_limit(linux):
    settings = config(enforcement_approved=True, max_new_bans_per_minute=1)
    fake = FakeNft(settings)
    fake.lose_readback = True
    firewall = ScopedNftFirewall(settings, runner=fake, monotonic=lambda: 100)
    with pytest.raises(ProxyFirewallError, match="read-back"):
        firewall.sync([ProxyBan("198.51.100.1", 130)], mode="enforce", now=100)
    before = len(fake.calls)
    with pytest.raises(ProxyFirewallError, match="New-ban rate"):
        firewall.sync([ProxyBan("198.51.100.2", 130)], mode="enforce", now=100)
    assert len(fake.calls) == before


def test_slow_check_does_not_refresh_expired_absolute_ban(linux):
    settings = config(enforcement_approved=True, max_ttl_seconds=30)
    fake = FakeNft(settings)
    moments = iter((100, 131))
    firewall = ScopedNftFirewall(settings, runner=fake, monotonic=lambda: next(moments))
    result = firewall.sync([ProxyBan("198.51.100.1", 130)], mode="enforce", now=100)
    assert result.applied and result.plan.bans == ()
    mutations = [kw["input"] for args, kw in fake.calls if args[1:] == ["-f", "-"]]
    assert "add element" not in mutations[0]


def test_readback_rejects_indefinite_or_excessive_kernel_timeout(linux):
    settings = config(enforcement_approved=True, max_ttl_seconds=30)
    firewall = ScopedNftFirewall(settings)
    for timeout in (None, 0, float("inf"), 31, True):
        objects = native_objects(settings, ["198.51.100.1"])
        objects[1]["set"]["elem"][0]["elem"]["timeout"] = timeout
        with pytest.raises(ProxyFirewallError, match="finite timeout"):
            firewall._members(objects)


def test_new_ban_and_sync_throttles_are_monotonic_and_fail_without_writes(linux):
    settings = config(enforcement_approved=True, max_new_bans_per_minute=1)
    fake = FakeNft(settings)
    tick = [100]
    firewall = ScopedNftFirewall(settings, runner=fake, monotonic=lambda: tick[0])
    first = [ProxyBan("198.51.100.1", 200)]
    firewall.sync(first, mode="enforce", now=100)
    before = len(fake.calls)
    with pytest.raises(ProxyFirewallError, match="sync rate"):
        firewall.sync(first, mode="enforce", now=100)
    tick[0] += 2
    with pytest.raises(ProxyFirewallError, match="New-ban rate"):
        firewall.sync(first + [ProxyBan("198.51.100.2", 200)], mode="enforce", now=102)
    assert len(fake.calls) == before
    tick[0] = 161
    assert firewall.sync(first + [ProxyBan("198.51.100.2", 200)], mode="enforce", now=161).applied


def test_remove_touches_only_exact_owned_table_and_is_idempotent(linux):
    settings = config(enforcement_approved=True)
    fake = FakeNft(settings)
    fake.objects = native_objects(settings, ["198.51.100.1"])
    firewall = ScopedNftFirewall(settings, runner=fake)
    assert firewall.remove(mode="enforce").applied
    scripts = [kwargs["input"] for args, kwargs in fake.calls if args[1:] == ["-f", "-"]]
    assert scripts == [f"delete table inet {settings.table_name}\n"]
    assert firewall.remove(mode="enforce").reason == "already_absent"
