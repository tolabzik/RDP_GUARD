"""Proxy enrollment must not turn a shared relay into a local ban target."""
import copy

import pytest

from conftest import activate, failures
from rdp_guard.proxy_client import binding_id, validate_binding
from rdp_guard.windows.proxy_export import utc
from test_web import ORIGIN, login, web as web


RELAY = "45.144.220.53"


def binding(guard):
    directory = guard.data_dir / "proxy"
    directory.mkdir(exist_ok=True)
    result = dict(enabled=True, agent_url="https://proxy.example:8443", stream_id="rdp", backend_id="windows",
                  computer="WIN-TEST", relay_ips=[RELAY], mode="monitor")
    for key in ("ca_file", "cert_file", "key_file"):
        path = directory / (key + ".pem")
        path.write_text("test fixture; never used for networking")
        result[key] = str(path)
    return result


def configure(guard, *, disabled=False):
    guard.dispatch("proxy-configure", {"binding": binding(guard)}, "test")
    if disabled:
        guard.dispatch("proxy-configure", {"binding": {"enabled": False}}, "test")


def proof(guard):
    cfg = guard.store.get("proxy_binding")
    return dict(binding_id=binding_id(cfg), enforcement_allowed=True, transport_healthy=True,
                healthy=True, capture_healthy=True, error="", stream_id=cfg["stream_id"],
                backend_id=cfg["backend_id"], computer=cfg["computer"],
                updated_at_utc=utc(guard.clock()), last_sent_utc=utc(guard.clock()))


@pytest.mark.parametrize("disabled", [False, True])
@pytest.mark.parametrize("source", [RELAY, "::ffff:" + RELAY])
def test_relay_is_never_automatically_blocked_even_after_exchange_disabled(guard, disabled, source):
    activate(guard)
    configure(guard, disabled=disabled)
    failures(guard, ip=source)
    assert guard.store.rows("SELECT * FROM blocks WHERE ended IS NULL") == []
    assert guard.firewall.backend.list_rules() == []
    assert {row["disposition"] for row in guard.store.rows("SELECT disposition FROM events")} == {"proxy-relay"}
    # Excluding infrastructure must not disable direct-client detection.
    failures(guard, start=100, ip="198.51.100.9")
    assert guard.store.rows("SELECT network FROM blocks WHERE ended IS NULL") == [{"network": "198.51.100.9/32"}]


@pytest.mark.parametrize("disabled", [False, True])
@pytest.mark.parametrize("network", [RELAY, "45.144.220.0/24", "::ffff:45.144.220.53"])
def test_relay_and_containing_networks_cannot_be_manually_blocked(guard, disabled, network):
    configure(guard, disabled=disabled)
    with pytest.raises(ValueError, match="shared proxy"):
        guard.dispatch("block", {"network": network}, "test")
    assert guard.store.rows("SELECT * FROM blocks") == []


def test_enrollment_removes_existing_overlapping_blocks_and_keeps_whitelist_separate(guard):
    activate(guard)
    guard.dispatch("block", {"network": "45.144.220.0/24"}, "test")
    guard.dispatch("block", {"network": "198.51.100.9"}, "test")
    before = guard.store.rows("SELECT * FROM whitelist")
    configure(guard)
    assert guard.store.rows("SELECT * FROM whitelist") == before
    assert not guard.trusted(RELAY)
    assert guard.relay_ips() == [RELAY]
    assert guard.store.rows("SELECT network FROM blocks WHERE ended IS NULL") == [{"network": "198.51.100.9/32"}]
    removed = guard.store.rows("SELECT status,ended FROM blocks WHERE network='45.144.220.0/24'")[0]
    assert removed["status"] == "proxy-relay" and removed["ended"] == guard.clock()
    assert all(rule.addresses == ("198.51.100.9/32",) for rule in guard.firewall.backend.list_rules())


@pytest.mark.parametrize("disabled", [False, True])
def test_blacklist_import_rejects_whole_batch_if_it_contains_shared_relay(guard, disabled):
    configure(guard, disabled=disabled)
    with pytest.raises(ValueError, match="protected"):
        guard.dispatch("import-lists", {"kind": "blacklist", "entries": [
            {"network": "198.51.100.9"}, {"network": "45.144.220.0/24"}]}, "test")
    assert guard.store.rows("SELECT * FROM blocks") == []


def test_proxy_endpoints_require_authentication_and_mutations_require_csrf(web):
    client, dispatcher = web
    for operation in ("proxy-status", "proxy-configure", "proxy-unblock"):
        assert client.post("/api/rpc", headers=ORIGIN, json={"op": operation}).status_code == 401
    csrf = login(client)
    request = {"op": "proxy-configure", "args": {"binding": binding(dispatcher.guard)}}
    assert client.post("/api/rpc", headers=ORIGIN, json=request).status_code == 401
    assert dispatcher.guard.store.get("proxy_binding") is None
    assert client.post("/api/rpc", headers=ORIGIN | {"x-csrf-token": csrf}, json=request).status_code == 200
    unblock = {"op": "proxy-unblock", "args": {"client_ip": "198.51.100.9"}}
    assert client.post("/api/rpc", headers=ORIGIN, json=unblock).status_code == 401
    assert client.post("/api/rpc", headers=ORIGIN | {"x-csrf-token": csrf}, json=unblock).status_code == 200
    assert dispatcher.guard.store.get("proxy_unblock_queue")[0]["client_ip"] == "198.51.100.9"


@pytest.mark.parametrize("changes", [
    {"updated_at_utc": "2000-01-01T00:00:00Z"},
    {"last_sent_utc": "2000-01-01T00:00:00Z"},
    {"updated_at_utc": "2999-01-01T00:00:00Z"},
    {"binding_id": "different"}, {"enforcement_allowed": "true"},
    {"healthy": False}, {"transport_healthy": False}, {"capture_healthy": False},
    {"error": "capture failed"},
])
def test_enforcement_cannot_use_stale_unhealthy_or_wrong_binding_status(guard, changes):
    configure(guard)
    guard.store.set("proxy_status", proof(guard) | changes)
    updated = guard.store.get("proxy_binding") | {"mode": "enforce"}
    with pytest.raises(ValueError, match="Fresh validated"):
        guard.dispatch("proxy-configure", {"binding": updated, "confirmation": "ENABLE PROXY BLOCKS"}, "test")
    assert guard.store.get("proxy_binding")["mode"] == "monitor"


def test_enforcement_transition_must_keep_same_endpoint_and_credentials(guard):
    configure(guard)
    guard.store.set("proxy_status", proof(guard))
    updated = guard.store.get("proxy_binding") | {"mode": "enforce", "agent_url": "https://other.example"}
    with pytest.raises(ValueError, match="Fresh validated"):
        guard.dispatch("proxy-configure", {"binding": updated, "confirmation": "ENABLE PROXY BLOCKS"}, "test")


def test_validated_mode_only_transition_requires_explicit_confirmation(guard):
    configure(guard)
    guard.store.set("proxy_status", proof(guard))
    updated = guard.store.get("proxy_binding") | {"mode": "enforce"}
    with pytest.raises(ValueError, match="confirmation"):
        guard.dispatch("proxy-configure", {"binding": updated}, "test")
    guard.dispatch("proxy-configure", {"binding": updated, "confirmation": "ENABLE PROXY BLOCKS"}, "test")
    assert guard.store.get("proxy_binding")["mode"] == "enforce"
    assert guard.store.get("proxy_status") == {}


def test_status_from_an_old_binding_is_stale_even_with_recent_timestamp(guard):
    configure(guard)
    guard.store.set("proxy_status", proof(guard) | {"binding_id": "old"})
    assert guard.dispatch("proxy-status", {}, "test")["stale"] is True


@pytest.mark.parametrize("value", ["127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1", "255.255.255.255", True])
def test_binding_rejects_protected_or_non_ip_relay_values(guard, value):
    cfg = binding(guard)
    cfg["relay_ips"] = [value]
    with pytest.raises(ValueError):
        validate_binding(guard.data_dir, cfg)


def test_binding_normalizes_mapped_ipv4_and_rejects_unknown_fields(guard):
    cfg = binding(guard)
    cfg["relay_ips"] = [RELAY, "::ffff:" + RELAY]
    assert validate_binding(guard.data_dir, cfg)["relay_ips"] == [RELAY]
    invalid = copy.deepcopy(cfg)
    invalid["disable_tls_verification"] = True
    with pytest.raises(ValueError, match="Unknown"):
        validate_binding(guard.data_dir, invalid)
    with pytest.raises(ValueError, match="Unknown"):
        validate_binding(guard.data_dir, {"enabled": False, "extra": "ignored"})


def test_proxy_ui_describes_validation_gate_and_requested_mode_truthfully(web):
    client, _ = web
    login(client)
    assert 'data-view="proxy"' in client.get("/").text
    script = client.get("/static/app.js").text
    proxy_view = script[script.index("async function proxyView()"):script.index("async function settingsView()")]
    assert "экспериментальная ветка" in proxy_view
    assert "Автоблокировки закрыты до проверки на изолированном стенде" in proxy_view
    assert "Блокировки запрошены" in proxy_view and "Нет свежего подтверждения" in proxy_view
    assert "подтверждённом ACTIVE" in proxy_view
