import copy
import json
from pathlib import Path
import ssl
import threading
from types import SimpleNamespace
import uuid

import pytest

from rdp_guard.proxy_client import ProxyTransport, ProxyWorker, RESPONSE_LIMIT, binding_id, sanitize_status, validate_binding
from rdp_guard.storage import Store
from rdp_guard.windows.proxy_export import NativeProxyExporter
from test_native_proxy_export import Api, NOW


@pytest.fixture
def guard(tmp_path):
    credentials = tmp_path / "proxy"
    credentials.mkdir()
    cfg = dict(enabled=True, agent_url="https://proxy.example:8443", stream_id="rdp", backend_id="win",
               computer="WIN-TEST", relay_ips=["45.144.220.53"], mode="monitor")
    for field in ("ca_file", "cert_file", "key_file"):
        path = credentials / (field + ".pem")
        path.write_text("test fixture")
        cfg[field] = str(path)
    store = Store(tmp_path / "test.db")
    store.set("proxy_binding", cfg)
    result = SimpleNamespace(store=store, data_dir=tmp_path, lock=threading.RLock(), mode="MONITOR ONLY",
                             emergency_path=tmp_path / "emergency.disabled", lease_path=tmp_path / "lease.json")
    yield result
    store.close()


def receipt():
    return {"ok": True, "status": {"healthy": True, "capture_healthy": True, "matched": 1,
                                   "mode": "monitor", "error": "", "stream_id": "rdp",
                                   "backend_id": "win", "computer": "WIN-TEST"}, "results": []}


def worker(guard, *, sender=None, now=None, exporter=None):
    now = now or [NOW]
    sent = []

    class Transport:
        def post(self, endpoint, envelope):
            assert not guard.lock._is_owned()
            sent.append(copy.deepcopy(envelope))
            return sender(endpoint, envelope) if sender else receipt()

    result = ProxyWorker(guard, threading.Event(),
                         exporter=exporter or NativeProxyExporter(Api(), clock=lambda: now[0]),
                         transport_factory=lambda cfg: Transport(), clock=lambda: now[0])
    return result, sent


def test_disabled_binding_has_no_export_network_or_persistence(guard):
    guard.store.set("proxy_binding", {"enabled": False})
    probe, sent = worker(guard, exporter=SimpleNamespace(export=lambda *a, **k: pytest.fail("export called")))
    probe.step()
    assert sent == [] and guard.store.get("proxy_status") is None


def test_complete_export_is_sent_without_guard_lock_and_receipt_is_saved(guard):
    probe, sent = worker(guard)
    probe.step()
    assert sent[0]["stream_id"] == "rdp" and sent[0]["mode"] == "monitor"
    assert guard.store.get("proxy_outbox") is None
    assert guard.store.get("proxy_status")["transport_healthy"] is True


def test_retry_survives_worker_restart_and_does_not_reexport(guard):
    def failed(*args):
        raise OSError("offline")
    probe, sent = worker(guard, sender=failed)
    with pytest.raises(OSError):
        probe.step()
    pending = guard.store.get("proxy_outbox")
    retry, later = worker(guard, exporter=SimpleNamespace(export=lambda *a, **k: pytest.fail("reexported")))
    retry.step()
    assert later[0]["document"] == pending["document"] == sent[0]["document"]
    assert guard.store.get("proxy_outbox") is None


def test_old_outbox_expires_and_fresh_export_failure_sends_nothing(guard):
    probe, _ = worker(guard, sender=lambda *a: (_ for _ in ()).throw(OSError()))
    with pytest.raises(OSError):
        probe.step()
    expired, sent = worker(guard, now=[NOW+121],
                           exporter=SimpleNamespace(export=lambda *a, **k: (_ for _ in ()).throw(ValueError())))
    with pytest.raises(ValueError):
        expired.step()
    assert sent == [] and guard.store.get("proxy_outbox") is None


@pytest.mark.parametrize("active,confirmed,emergency,expected", [
    (False, True, False, "monitor"), (True, False, False, "monitor"),
    (True, True, True, "monitor"), (True, True, False, "enforce"),
])
def test_enforce_requires_confirmed_active_guard(guard, active, confirmed, emergency, expected):
    cfg = guard.store.get("proxy_binding")
    cfg["mode"] = "enforce"
    guard.store.set("proxy_binding", cfg)
    guard.mode = "ACTIVE" if active else "MONITOR ONLY"
    guard.lease_path.write_text(json.dumps({"confirmed": confirmed, "heartbeat": NOW, "deadline": None}))
    if emergency:
        guard.emergency_path.touch()
    probe, sent = worker(guard)
    probe.step()
    assert sent[0]["mode"] == expected


def test_retry_demotes_after_emergency_and_never_promotes_old_monitoring(guard):
    cfg = guard.store.get("proxy_binding")
    cfg["mode"] = "enforce"
    guard.store.set("proxy_binding", cfg)
    guard.mode = "ACTIVE"
    guard.lease_path.write_text(json.dumps({"confirmed": True, "heartbeat": NOW, "deadline": None}))
    failed, _ = worker(guard, sender=lambda *a: (_ for _ in ()).throw(OSError()))
    with pytest.raises(OSError):
        failed.step()
    guard.emergency_path.touch()
    retry, sent = worker(guard)
    retry.step()
    assert sent[0]["mode"] == "monitor"


def test_binding_changed_during_export_does_not_send(guard):
    exporter = NativeProxyExporter(Api(), clock=lambda: NOW)

    def changed(*args, **kwargs):
        document = exporter.export(*args, **kwargs)
        guard.store.set("proxy_binding", {"enabled": False})
        return document
    probe, sent = worker(guard, exporter=SimpleNamespace(export=changed))
    probe.step()
    assert sent == []


def test_receipt_for_other_binding_is_not_acknowledged(guard):
    wrong = receipt()
    wrong["status"]["computer"] = "OTHER"
    probe, _ = worker(guard, sender=lambda *a: wrong)
    with pytest.raises(ValueError, match="binding"):
        probe.step()
    assert guard.store.get("proxy_outbox") is not None


def test_queued_unblock_is_delivered_before_even_failing_export_and_acked_by_id(guard):
    cfg = validate_binding(guard.data_dir, guard.store.get("proxy_binding"))
    item = dict(id=str(uuid.uuid4()), client_ip="192.0.2.20", created=NOW, binding_id=binding_id(cfg))
    guard.store.set("proxy_unblock_queue", [item])
    endpoints = []

    def sender(endpoint, envelope):
        endpoints.append(endpoint)
        assert envelope["client_ip"] == "192.0.2.20"
        # Concurrent dispatch appends another request while the first request is in flight.
        guard.store.set("proxy_unblock_queue", [item, dict(item, id=str(uuid.uuid4()))])
        return receipt()
    probe, _ = worker(guard, sender=sender,
                       exporter=SimpleNamespace(export=lambda *a, **k: (_ for _ in ()).throw(ValueError())))
    with pytest.raises(ValueError):
        probe.step()
    assert endpoints == ["/v1/unblock"]
    remaining = guard.store.get("proxy_unblock_queue")
    assert len(remaining) == 1 and remaining[0]["id"] != item["id"]


def test_expired_or_other_binding_unblock_is_never_sent(guard):
    cfg = validate_binding(guard.data_dir, guard.store.get("proxy_binding"))
    item = dict(id=str(uuid.uuid4()), client_ip="192.0.2.20", created=NOW-121, binding_id=binding_id(cfg))
    guard.store.set("proxy_unblock_queue", [item, dict(item, created=NOW, binding_id="other")])
    probe, sent = worker(guard)
    probe.step()
    assert len(sent) == 1 and "document" in sent[0]
    assert guard.store.get("proxy_unblock_queue") == []
    assert guard.store.get("proxy_status")["discarded_unblock_requests"] == 2


@pytest.mark.parametrize("url", ["http://host", "https://user:pw@host", "https://host/path", "https://host?token=a",
                                 "https://host:0"])
def test_binding_rejects_non_origin_or_non_tls_urls(guard, url):
    cfg = guard.store.get("proxy_binding")
    cfg["agent_url"] = url
    with pytest.raises(ValueError):
        validate_binding(guard.data_dir, cfg)


def test_credentials_cannot_escape_directory_or_use_links(guard, tmp_path):
    cfg = guard.store.get("proxy_binding")
    outside = tmp_path / "outside.pem"
    outside.write_text("not a credential")
    cfg["key_file"] = str(outside)
    with pytest.raises(ValueError, match="protected proxy directory"):
        validate_binding(guard.data_dir, cfg)
    link = tmp_path / "proxy" / "linked.pem"
    link.symlink_to(outside)
    cfg["key_file"] = str(link)
    with pytest.raises(ValueError, match="links"):
        validate_binding(guard.data_dir, cfg)


def test_receipt_only_keeps_allowed_bounded_fields():
    value = receipt()
    value["status"].update(secret="do not keep", error="C:/private/key.pem", matched=True)
    value["results"] = [{"client_ip": "192.0.2.1", "raw_xml": "secret", "reason": "a"*1000}]
    result = sanitize_status(value)
    assert "secret" not in result and "matched" not in result
    assert "private" not in result["error"] and "raw_xml" not in result["results"][0]
    assert len(result["results"][0]["reason"]) == 200


def test_transport_verifies_mtls_uses_timeout_and_rejects_large_response(guard, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "https://must-not-be-used")
    calls = {}
    context = SimpleNamespace(load_cert_chain=lambda **kwargs: calls.update(credentials=kwargs))

    def context_factory(**kwargs):
        calls["context"] = kwargs
        return context

    class Connection:
        def __init__(self, host, port, **kwargs):
            calls.update(host=host, port=port, options=kwargs)

        def request(self, method, path, **kwargs):
            calls.update(method=method, path=path)

        def getresponse(self):
            return SimpleNamespace(status=200, read=lambda n: b" "*n)

        def close(self):
            calls["closed"] = True

    cfg = validate_binding(guard.data_dir, guard.store.get("proxy_binding"))
    transport = ProxyTransport(cfg, Connection, context_factory)
    with pytest.raises(ValueError, match="response exceeds"):
        transport.post("/v1/status", {"stream_id": "rdp", "backend_id": "win"})
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert calls["host"] == "proxy.example" and calls["options"]["timeout"] == 5
    assert calls["closed"] and RESPONSE_LIMIT == 1024 * 1024
    assert Path(calls["context"]["cafile"]).is_relative_to(guard.data_dir / "proxy")
