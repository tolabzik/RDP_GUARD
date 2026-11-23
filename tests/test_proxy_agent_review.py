"""Adversarial lifecycle/control-plane regressions for the experimental agent."""
from copy import deepcopy
import hashlib
import socket
import sqlite3
import ssl
import threading
import time

import pytest

from rdp_guard.proxy_agent import Agent, load_config, make_server
from rdp_guard.proxy_client import ProxyTransport
from test_proxy_agent import certificates, config, setup_agent


def test_status_exposes_local_enforcement_gate_for_windows_activation(tmp_path):
    agent, _, _, _, _ = setup_agent(tmp_path, enforce=True)
    assert agent.status()["enforcement_allowed"] is True
    agent.config["enforcement_validated"] = False
    assert agent.status()["enforcement_allowed"] is False


@pytest.mark.parametrize("field,value", [("max_records", True), ("max_records", 10**9),
                                        ("max_log_bytes", 0), ("epoch_seconds", -1),
                                        ("epoch_seconds", float("inf")), ("nginx_pid_namespace", "")])
def test_check_config_rejects_bad_capture_resource_limits(tmp_path, field, value):
    cfg = config(tmp_path)
    cfg[field] = value
    with pytest.raises(ValueError):
        load_config(cfg)


def test_mapped_listener_is_normalized_before_scope_binding(tmp_path):
    cfg = config(tmp_path)
    cfg["listener_ip"] = "::ffff:203.0.113.10"
    assert load_config(cfg)["listener_ip"] == "203.0.113.10"


def test_matching_cannot_renew_after_windows_heartbeat_expires(tmp_path):
    agent, envelope, clock, capture, firewall = setup_agent(tmp_path, enforce=True)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    original = capture.snapshot
    calls = [0]

    def snapshot():
        calls[0] += 1
        if calls[0] == 2:
            clock[0] += 20
        return original()

    capture.snapshot = snapshot
    agent.tick()
    assert firewall.calls[-1] == {}
    assert agent.status()["active_bans"] == 0
    assert agent.status()["mode"] == "monitor"


def test_generation_change_during_match_does_not_renew(tmp_path):
    agent, envelope, _, capture, firewall = setup_agent(tmp_path, enforce=True)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    original = capture.snapshot
    calls = [0]

    def snapshot():
        calls[0] += 1
        state = original()
        if calls[0] == 2:
            state["epoch"] = "replacement-epoch"
        return state

    capture.snapshot = snapshot
    agent.tick()
    assert firewall.calls[-1] == {}
    assert not agent.status()["healthy"]


def test_decision_and_ban_are_one_transaction(tmp_path):
    agent, envelope, _, _, _ = setup_agent(tmp_path, enforce=True)
    agent.db.executescript("""
        CREATE TRIGGER simulate_disk_failure BEFORE INSERT ON bans
        BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END;
    """)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    with pytest.raises(sqlite3.IntegrityError):
        agent.tick()
    assert agent.db.execute("SELECT COUNT(*) FROM bans").fetchone()[0] == 0
    assert agent.db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 1
    assert agent.db.execute("SELECT COUNT(*) FROM decisions WHERE expires IS NOT NULL").fetchone()[0] == 0


def test_protocol_change_cannot_reuse_existing_state(tmp_path):
    agent, _, clock, capture, _ = setup_agent(tmp_path)
    changed = dict(agent.config, protocols=["tcp", "udp"])
    agent.close()
    with pytest.raises(ValueError, match="different proxy binding"):
        Agent(changed, capture, clock=lambda: clock[0])


def test_status_and_current_client_result_follow_verified_lease(tmp_path):
    agent, envelope, clock, _, _ = setup_agent(tmp_path, enforce=True)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    agent.tick()
    assert len(agent.results()) == 1  # multiple native decisions, one current client
    assert agent.results()[0]["status"] == "blocked"
    # A later observation on the same client must not hide a current ban.
    agent.db.execute("UPDATE decisions SET status='observed' WHERE attempts=2")
    assert agent.results()[0]["status"] == "blocked"
    clock[0] += 31
    assert agent.status()["active_bans"] == 0
    assert agent.results()[0]["status"] == "suspended"


def test_unblock_is_pending_until_firewall_readback(tmp_path):
    agent, envelope, _, _, firewall = setup_agent(tmp_path, enforce=True)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    agent.tick()
    result = agent.handle("/v1/unblock", dict(stream_id="rdp", backend_id="windows",
                                           client_ip="198.51.100.7"), "a" * 64)
    assert result["status"]["active_bans"] == 1
    assert result["results"][0]["status"] == "removal_pending"
    agent.tick()
    assert firewall.calls[-1] == {}
    assert agent.status()["active_bans"] == 0
    assert agent.results()[0]["status"] == "removed"


def test_new_whitelist_suppresses_existing_logical_ban(tmp_path):
    agent, envelope, clock, _, firewall = setup_agent(tmp_path, enforce=True)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    agent.tick()
    agent.config["whitelist"].append("198.51.100.7/32")
    clock[0] += 5
    agent.tick()
    assert firewall.calls[-1] == {}
    assert agent.status()["active_bans"] == 0
    assert agent.results()[0]["status"] == "whitelisted"


def test_manual_unblock_suppression_has_bounded_capacity(tmp_path, monkeypatch):
    agent, _, clock, _, _ = setup_agent(tmp_path)
    monkeypatch.setattr("rdp_guard.proxy_agent.MAX_SUPPRESSIONS", 1)
    request = dict(stream_id="rdp", backend_id="windows", client_ip="198.51.100.1")
    agent.handle("/v1/unblock", request, "a" * 64)
    agent.handle("/v1/unblock", request, "a" * 64)  # retry doesn't consume another entry
    with pytest.raises(ValueError, match="capacity"):
        agent.handle("/v1/unblock", dict(request, client_ip="198.51.100.2"), "a" * 64)
    clock[0] += agent.config["window_seconds"]
    agent.handle("/v1/unblock", dict(request, client_ip="198.51.100.2"), "a" * 64)
    assert agent.db.execute("SELECT COUNT(*) FROM suppression").fetchone()[0] == 1


def test_actual_verified_subset_is_reported_not_requested_bans(tmp_path):
    agent, envelope, _, _, firewall = setup_agent(tmp_path, enforce=True)
    agent.handle("/v1/evidence", envelope, "a" * 64)
    firewall.sync = lambda _: {}  # finite entry expired during native check
    agent.tick()
    assert agent.status()["active_bans"] == 0
    assert agent.results()[0]["status"] == "suspended"


def test_monitor_queue_cannot_gain_authority_from_future_enforce_snapshot(tmp_path):
    agent, envelope, _, capture, _ = setup_agent(tmp_path, enforce=True)
    envelope["mode"] = "monitor"
    capture.value["healthy"] = False
    agent.handle("/v1/evidence", envelope, "a" * 64)
    later = deepcopy(envelope)
    later["mode"] = "enforce"
    later["document"]["requested_end_utc"] = later["document"]["requested_end_utc"].replace(":40", ":41")
    agent.handle("/v1/evidence", later, "a" * 64)
    capture.value["healthy"] = True
    agent.tick()
    assert agent.db.execute("SELECT COUNT(*) FROM bans").fetchone()[0] == 0


def test_real_tls_incomplete_body_has_total_deadline_and_server_recovers(tmp_path, monkeypatch):
    certificates(tmp_path)
    agent, _, _, _, _ = setup_agent(tmp_path)
    der = ssl.PEM_cert_to_DER_cert((tmp_path / "client.pem").read_text())
    agent.config["client_sha256"] = hashlib.sha256(der).hexdigest()
    agent.config["api_port"] = 0
    monkeypatch.setattr("rdp_guard.proxy_agent.REQUEST_DEADLINE_SECONDS", 0.2)
    server = make_server(agent)
    # Expected close of an incomplete HTTP request is not a useful test traceback.
    server.handle_error = lambda *_: None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    context = ssl.create_default_context(cafile=str(tmp_path / "ca.pem"))
    context.load_cert_chain(str(tmp_path / "client.pem"), str(tmp_path / "client.key"))
    binding = dict(agent_url=f"https://127.0.0.1:{server.server_address[1]}",
                   ca_file=str(tmp_path / "ca.pem"), cert_file=str(tmp_path / "client.pem"),
                   key_file=str(tmp_path / "client.key"))
    try:
        with socket.create_connection(server.server_address, timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
                started = time.monotonic()
                sock.sendall(b"POST /v1/evidence HTTP/1.0\r\nContent-Type: application/json\r\n"
                             b"Content-Length: 100\r\n\r\n{")
                assert sock.recv(1) == b""
                assert time.monotonic() - started < 1.5
        receipt = ProxyTransport(binding).post("/v1/status", dict(stream_id="rdp", backend_id="windows"))
        assert receipt["ok"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
