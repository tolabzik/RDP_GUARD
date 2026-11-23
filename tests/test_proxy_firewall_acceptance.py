"""Portable checks that the opt-in native acceptance harness stays isolated."""
import importlib.util
import io
from pathlib import Path
import subprocess

import pytest

from rdp_guard.proxy_firewall import ProxyBan, ProxyFirewallConfig, build_plan
from test_proxy_firewall import FakeNft


PATH = Path(__file__).resolve().parents[1] / "scripts" / "Test-ProxyFirewall-Linux.py"
spec = importlib.util.spec_from_file_location("proxy_firewall_acceptance", PATH)
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def test_default_is_help_without_any_host_operation(monkeypatch, capsys):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Default invocation must not touch host state")

    monkeypatch.setattr(acceptance.shutil, "which", forbidden)
    monkeypatch.setattr(acceptance, "Lab", forbidden)
    assert acceptance.main([]) == 0
    assert "--run" in capsys.readouterr().out


def test_run_refuses_non_linux_before_creating_any_namespace(monkeypatch):
    monkeypatch.setattr(acceptance.sys, "platform", "darwin")
    with pytest.raises(SystemExit) as exc:
        acceptance.main(["--run"])
    assert exc.value.code == 2


def test_nft_adapter_runner_always_enters_only_its_namespace():
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "", "")

    runner = acceptance.NamespaceNftRunner("/usr/sbin/ip", "/usr/sbin/nft", "owned-proxy", runner=run)
    runner(["/usr/sbin/nft", "-f", "-"], input="rules", timeout=100, text=True)
    assert calls == [(["/usr/sbin/ip", "netns", "exec", "owned-proxy", "/usr/sbin/nft", "-f", "-"],
                      {"input": "rules", "timeout": 10, "text": True})]
    with pytest.raises(acceptance.AcceptanceError):
        runner(["/bin/sh", "-c", "nft flush ruleset"])
    assert len(calls) == 1


class Server:
    def __init__(self):
        self.stdout, self.stderr = io.StringIO('{"ready": true}\n'), io.StringIO()
        self.terminated = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout):
        assert timeout == 3
        return 0


def test_lab_network_firewall_and_sysctl_commands_are_namespace_scoped(monkeypatch):
    calls, child_calls = [], []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "", "")

    server = Server()
    monkeypatch.setattr(acceptance.select, "select", lambda *_: ([server.stdout], [], []))
    monkeypatch.setattr(acceptance.subprocess, "Popen", lambda args, **_: child_calls.append(args) or server)
    lab = acceptance.Lab("/usr/sbin/ip", "/usr/sbin/nft", runner=run)
    lab.setup()
    assert len(set(lab.names.values())) == 3
    for args, _ in calls:
        assert args[0] == "/usr/sbin/ip"
        if args[1:3] == ["netns", "add"]:
            assert args[3] in lab.names.values()
        elif args[1] == "-n":
            assert args[2] in lab.names.values()
        else:
            assert args[1:3] == ["netns", "exec"] and args[3] in lab.names.values()
    assert child_calls[0][:4] == ["/usr/sbin/ip", "netns", "exec", lab.names["backend"]]
    sysctl_call = next(args for args, _ in calls if "ip_forward" in args[-1])
    assert sysctl_call[:4] == ["/usr/sbin/ip", "netns", "exec", lab.names["proxy"]]
    assert lab.cleanup() == [] and server.terminated
    deleted = [args[-1] for args, _ in calls if args[1:3] == ["netns", "delete"]]
    assert deleted == list(reversed(lab.names.values()))


def test_failed_namespace_creation_never_deletes_someone_elses_namespace():
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ["netns", "add"] and sum(c[1:3] == ["netns", "add"] for c in calls) == 2:
            raise acceptance.AcceptanceError("name already exists")
        return subprocess.CompletedProcess(args, 0, "", "")

    lab = acceptance.Lab("ip", "nft", runner=run)
    with pytest.raises(acceptance.AcceptanceError):
        lab.setup()
    assert lab.cleanup() == []
    assert [args[-1] for args in calls if args[1:3] == ["netns", "delete"]] == [lab.names["client"]]


def test_cleanup_continues_after_one_namespace_delete_fails():
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1 if len(calls) == 1 else 0, "", "simulated failure")

    lab = acceptance.Lab("ip", "nft", runner=run)
    lab.created = list(lab.names.values())
    errors = lab.cleanup()
    assert len(errors) == 1
    assert len(calls) == 3


def test_unowned_namespace_cannot_receive_nft_or_network_command():
    lab = acceptance.Lab("ip", "nft")
    with pytest.raises(acceptance.AcceptanceError):
        lab.ns_command("proxy", "nft", "-f", "-")
    with pytest.raises(acceptance.AcceptanceError):
        lab.ip_command("proxy", "route", "add", "default", "via", "192.0.2.1")


def test_whitelist_acceptance_uses_native_sync_result_contract(monkeypatch):
    monkeypatch.setattr("rdp_guard.proxy_firewall.sys.platform", "linux")
    config = ProxyFirewallConfig("acceptance-test", acceptance.PUBLIC, acceptance.PUBLIC_PORT,
                                 whitelist=(acceptance.TRUSTED_CLIENT + "/32",), enforcement_approved=True,
                                 max_ttl_seconds=30)
    desired = [ProxyBan(acceptance.CLIENT, 130), ProxyBan(acceptance.TRUSTED_CLIENT, 130)]
    acceptance.assert_whitelist_plan(build_plan(config, desired, now=100))
    firewall = acceptance.ScopedNftFirewall(config, runner=FakeNft(config), monotonic=lambda: 100)
    result = firewall.sync(desired, mode="enforce", now=100)
    # A verified transaction is rebuilt from the filtered set, not raw input.
    assert result.plan.whitelisted == ()
    acceptance.assert_applied_clients(result, {acceptance.CLIENT})
    with pytest.raises(acceptance.AcceptanceError):
        acceptance.assert_applied_clients(result, {acceptance.CLIENT, acceptance.TRUSTED_CLIENT})
