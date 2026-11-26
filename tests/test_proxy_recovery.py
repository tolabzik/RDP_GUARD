from dataclasses import replace
import json
from pathlib import Path

import pytest

from rdp_guard.proxy_recovery import NpmRecovery, managed, select_stream
from rdp_guard.proxy_setup import Stream, SetupError
from test_proxy_agent import setup_agent


@pytest.fixture
def topology(tmp_path):
    stream = Stream("a" * 64, "npm", tmp_path, Path("2.conf"), "203.0.113.20", 33950,
                    25253, (("0.0.0.0", 25253),), False, False, "pid:[100]", 180)
    cfg = {"stream_id": "npm-2-25253", "backend_ip": "203.0.113.20", "backend_port": 33950,
           "listener_ip": "203.0.113.10", "listener_port": 25253,
           "nginx_log": str(tmp_path / "logs/rdpguard-stream-info.log"),
           "nginx_pid_namespace": "pid:[99]", "state_file": str(tmp_path / "state.sqlite3")}
    return cfg, stream


def test_managed_legacy_pairing_can_recover_without_new_keys(topology):
    cfg, _ = topology
    assert not managed(cfg)
    Path(cfg["state_file"]).with_name("setup-state.json").write_text(json.dumps({
        "schema": "rdpguard.proxy-setup.v1", "status": "paired", "windows_acknowledged": True}))
    assert managed(cfg)
    assert not managed(dict(cfg, recover_npm=False))


@pytest.mark.parametrize("changes", [
    {"backend_ip": "203.0.113.21"}, {"backend_port": 33951}, {"container_port": 25254},
    {"data_path": Path("/another")}, {"config_path": Path("3.conf")},
    {"bindings": (("203.0.113.99", 25253),)},
])
def test_rediscovery_never_moves_to_another_scope(topology, changes):
    cfg, stream = topology
    with pytest.raises(SetupError):
        select_stream(cfg, [replace(stream, **changes)])
    with pytest.raises(SetupError):
        select_stream(cfg, [stream, stream])


def test_restarted_container_identity_and_ntp_are_rechecked(topology, monkeypatch):
    from rdp_guard import proxy_recovery
    cfg, stream = topology
    synced, calls = [False], []
    def runner(args):
        calls.append(args)
        return "yes" if synced[0] else "no"
    monkeypatch.setattr(proxy_recovery, "discover_streams", lambda runner: [stream])
    resolver = NpmRecovery(cfg, runner)
    with pytest.raises(SetupError, match="NTP"):
        resolver()
    assert ["timedatectl", "set-ntp", "true"] in calls
    synced[0] = True
    result = resolver()
    assert result["nginx_pid_namespace"] == "pid:[100]"
    assert result["nginx_utc_offset_minutes"] == 180
    assert cfg["nginx_pid_namespace"] == "pid:[99]"


def test_results_search_pages_and_unblock_are_scoped(tmp_path):
    agent, _, _, _, _ = setup_agent(tmp_path)
    try:
        for i in range(120):
            agent.db.execute("INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (str(i), i, f"198.51.100.{i + 1}", str(i), i + 1, "observed", "proof", None, "monitor", "{}"))
        request = {"stream_id": "rdp", "backend_id": "windows", "query": "", "status": "",
                   "offset": 50, "sort": "attempts"}
        page = agent.handle("/v1/results", request, "a" * 64)
        assert page["total"] == 120 and len(page["results"]) == 50
        assert page["results"][0]["attempts"] == 70
        assert page["whitelist"] == agent.config["whitelist"]
        filtered = agent.handle("/v1/results", dict(request, offset=0, query="198.51.100.12"), "a" * 64)
        assert {r["client_ip"] for r in filtered["results"]} == {"198.51.100.12", "198.51.100.120"}
        with pytest.raises(PermissionError):
            agent.handle("/v1/results", dict(request, backend_id="another"), "a" * 64)
        with pytest.raises(PermissionError):
            agent.handle("/v1/results", request, "b" * 64)
        with pytest.raises(ValueError):
            agent.handle("/v1/results", dict(request, query="'; DROP TABLE decisions;"), "a" * 64)
        agent.handle("/v1/unblock", {"stream_id": "rdp", "backend_id": "windows", "client_ip": "198.51.100.12"}, "a" * 64)
        removed = agent.handle("/v1/results", dict(request, offset=0, status="removed"), "a" * 64)
        assert [r["client_ip"] for r in removed["results"]] == ["198.51.100.12"]
    finally:
        agent.close()
