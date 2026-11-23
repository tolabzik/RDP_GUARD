"""Pairing preserves local control, private keys and transactional configuration."""
import copy
import json
import os
from pathlib import Path
import threading
import time

import pytest

from rdp_guard.auth import Dispatcher
from rdp_guard.proxy_enrollment import EnrollmentManager, _private_directory, _read_private, _windows_private
from rdp_guard.proxy_pairing import PairingAuthority, PairingError, PairingRetryableError, create_pairing
from test_web import ORIGIN, login, web as web


RELAY = "45.144.220.53"


@pytest.fixture
def enrollment(guard, tmp_path):
    guard.clock = time.time
    settings = dict(agent_url="https://proxy.example:9443", stream_id="rdp", backend_id="windows",
                    listener_ip=RELAY, listener_port=45451, backend_ip="79.140.26.181", backend_port=45451,
                    relay_ips=[RELAY, "198.51.100.6"], whitelist=["203.0.113.10/32"], protocols=["tcp"])
    authority_dir = tmp_path / "linux-authority"
    document = create_pairing(authority_dir, settings)
    authority = PairingAuthority(document, authority_dir, lambda receipt: None)
    sent = []

    class Transport:
        def __init__(self, invitation):
            assert invitation == document

        def enroll(self, computer, csr):
            sent.append(dict(computer=computer, csr=csr))
            return authority.handle(dict(pairing_id=document["pairing_id"], token=document["token"],
                                         computer=computer, csr_pem=csr))

        def complete(self, computer, fingerprint):
            # ACK is illegal before all local credentials and binding are durable.
            binding = guard.store.get("proxy_binding")
            assert binding and binding["enabled"] is True
            assert Path(binding["key_file"]).is_file() and Path(binding["cert_file"]).is_file()
            return authority.complete(dict(pairing_id=document["pairing_id"], token=document["token"],
                                           computer=computer, client_sha256=fingerprint))

    manager = EnrollmentManager(guard, transport_factory=Transport, computer_reader=lambda: "WIN-TEST")
    guard.proxy_enrollment = manager
    yield document, manager, Transport, sent
    manager.close()
    authority.close()


def wait_done(manager):
    manager._thread.join(5)
    assert not manager._thread.is_alive(), manager.status()
    return manager.status()


def start(guard, document):
    return guard.dispatch("proxy-pair", {"document": document, "trusted_relay": RELAY}, "test")


def test_pairing_creates_local_private_key_and_only_explicit_relay_trust(guard, enrollment):
    document, manager, _, sent = enrollment
    preview = guard.dispatch("proxy-pair-preview", {"document": document}, "test")
    assert preview["computer"] == "WIN-TEST" and preview["mode"] == "monitor"
    assert not {"token", "ca_pem", "server_sha256", "pairing_id"} & preview.keys()
    assert start(guard, document)["state"] == "preparing"
    state = wait_done(manager)
    assert state["state"] == "paired" and state["handoff_pending"] is False
    binding = guard.store.get("proxy_binding")
    assert binding["enabled"] is True and binding["mode"] == "monitor"
    assert guard.mode == "MONITOR ONLY"
    assert guard.store.rows("SELECT network FROM whitelist") == [{"network": RELAY + "/32"}]
    assert sorted(guard.relay_ips()) == sorted(document["relay_ips"])
    assert not guard.trusted("198.51.100.6") and not guard.trusted("203.0.113.10")
    key = Path(binding["key_file"]).read_text()
    assert "PRIVATE KEY" in key and all("PRIVATE KEY" not in request["csr"] for request in sent)
    assert set(sent[0]) == {"computer", "csr"}
    for path in Path(binding["key_file"]).parent.iterdir():
        assert document["token"] not in path.read_text()
        if os.name != "nt":
            assert path.stat().st_mode & 0o077 == 0
    audit = json.dumps(guard.store.rows("SELECT * FROM audit"))
    status = json.dumps(guard.dispatch("proxy-status", {}, "test"))
    assert document["token"] not in audit + status
    assert key not in audit + status
    assert guard.firewall.backend.list_rules() == []


@pytest.mark.parametrize("mutation", ["expired", "extra", "invalid_ca", "invalid_pin", "token"])
def test_invalid_invitation_is_rejected_without_storage_or_secret_in_audit(guard, enrollment, mutation):
    document, _, _, _ = enrollment
    invalid = copy.deepcopy(document)
    if mutation == "expired":
        invalid["issued_at"] = guard.clock() - 700
        invalid["expires_at"] = guard.clock() - 100
    elif mutation == "extra":
        invalid["skip_verification"] = True
    elif mutation == "invalid_ca":
        invalid["ca_pem"] = document["token"]
    elif mutation == "invalid_pin":
        invalid["server_sha256"] = document["token"]
    else:
        invalid["token"] = "secret-that-must-not-appear"
    dispatcher = Dispatcher(guard)
    with pytest.raises(ValueError, match="invalid, unsupported or expired"):
        dispatcher({"op": "proxy-pair", "args": {"document": invalid, "trusted_relay": RELAY}},
                   {"role": "admin", "sid": "test"})
    assert guard.store.get("proxy_binding") is None
    assert not (guard.data_dir / "proxy").exists()
    audit = json.dumps(guard.store.rows("SELECT * FROM audit"))
    assert invalid["token"] not in audit


@pytest.mark.parametrize("relay", [None, "203.0.113.10", "127.0.0.1"])
def test_pairing_requires_declared_explicit_relay(guard, enrollment, relay):
    document, _, _, _ = enrollment
    with pytest.raises(ValueError, match="Explicitly select"):
        guard.dispatch("proxy-pair", {"document": document, "trusted_relay": relay}, "test")


def test_pairing_refuses_existing_binding_or_block_without_changing_it(guard, enrollment):
    document, _, _, _ = enrollment
    old = {"enabled": True, "sentinel": "preserve"}
    guard.store.set("proxy_binding", old)
    with pytest.raises(ValueError, match="Disable the existing"):
        start(guard, document)
    assert guard.store.get("proxy_binding") == old
    guard.store.set("proxy_binding", {"enabled": False})
    guard.dispatch("block", {"network": "45.144.220.0/24"}, "test")
    before = guard.store.rows("SELECT * FROM blocks")
    with pytest.raises(ValueError, match="overlaps"):
        start(guard, document)
    assert guard.store.rows("SELECT * FROM blocks") == before
    assert guard.store.rows("SELECT * FROM whitelist") == []


def test_network_does_not_hold_guard_lock_and_concurrent_import_is_rejected(guard, enrollment):
    document, manager, transport, _ = enrollment
    entered, release = threading.Event(), threading.Event()

    class Slow(transport):
        def enroll(self, computer, csr):
            entered.set()
            assert release.wait(5)
            return super().enroll(computer, csr)

    manager.transport_factory = Slow
    start(guard, document)
    assert entered.wait(5)
    try:
        assert guard.lock.acquire(timeout=0.1)
        guard.lock.release()
        assert guard.dispatch("status", {}, "test")["mode"] == "MONITOR ONLY"
        with pytest.raises(ValueError, match="already in progress"):
            start(guard, document)
    finally:
        release.set()
    assert wait_done(manager)["state"] == "paired"


def test_disable_during_inflight_enrollment_cancels_commit_even_if_binding_was_disabled(guard, enrollment):
    document, manager, transport, _ = enrollment
    entered, release = threading.Event(), threading.Event()

    class Slow(transport):
        def enroll(self, computer, csr):
            entered.set()
            assert release.wait(5)
            return super().enroll(computer, csr)

    manager.transport_factory = Slow
    guard.store.set("proxy_binding", {"enabled": False})
    start(guard, document)
    assert entered.wait(5)
    guard.dispatch("proxy-configure", {"binding": {"enabled": False}}, "test")
    release.set()
    assert wait_done(manager)["state"] == "cancelled"
    assert guard.store.get("proxy_binding") == {"enabled": False}
    assert guard.store.rows("SELECT * FROM whitelist") == []


def test_lost_receipt_retry_reuses_same_csr_and_private_key(guard, enrollment):
    document, manager, transport, sent = enrollment

    class LostResponse(transport):
        calls = 0

        def enroll(self, computer, csr):
            result = super().enroll(computer, csr)
            self.calls += 1
            if self.calls == 1:
                raise PairingRetryableError("response lost")
            return result

    manager.transport_factory = LostResponse
    start(guard, document)
    assert wait_done(manager)["state"] == "paired"
    assert len(sent) == 2 and sent[0]["csr"] == sent[1]["csr"]


@pytest.mark.parametrize("field", ["client_pem", "client_sha256", "computer", "stream_id", "pairing_id"])
def test_bad_receipt_does_not_commit_or_trust_relay(guard, enrollment, field):
    document, manager, transport, _ = enrollment
    previous = {"enabled": False}
    guard.store.set("proxy_binding", previous)

    class BadReceipt(transport):
        def enroll(self, computer, csr):
            return super().enroll(computer, csr) | {field: "wrong"}

    manager.transport_factory = BadReceipt
    start(guard, document)
    assert wait_done(manager)["state"] == "failed"
    assert guard.store.get("proxy_binding") == previous
    assert guard.store.rows("SELECT * FROM whitelist") == []
    assert guard.relay_ips() == []


def test_transport_verification_failure_is_sanitized(guard, enrollment):
    document, manager, transport, _ = enrollment

    class PinMismatch(transport):
        def enroll(self, computer, csr):
            raise PairingError(document["token"] + " private backend error")

    manager.transport_factory = PinMismatch
    start(guard, document)
    state = wait_done(manager)
    assert state["state"] == "failed" and document["token"] not in json.dumps(state)
    assert guard.store.get("proxy_binding") is None


def test_restart_retry_recovers_persisted_identity_without_writing_token(guard, enrollment):
    document, manager, transport, sent = enrollment

    class Once(transport):
        def enroll(self, computer, csr):
            super().enroll(computer, csr)
            raise PairingError("simulated restart after issuance")

    manager.transport_factory = Once
    start(guard, document)
    assert wait_done(manager)["state"] == "failed"
    manager.transport_factory = transport
    start(guard, document)
    assert wait_done(manager)["state"] == "paired"
    assert len(sent) == 2 and sent[0]["csr"] == sent[1]["csr"]


def test_new_block_during_network_prevents_final_trust_commit(guard, enrollment):
    document, manager, transport, _ = enrollment

    class ConflictingBlock(transport):
        def enroll(self, computer, csr):
            with guard.lock:
                guard.add_block(RELAY, "Review this conflict", "test")
            return super().enroll(computer, csr)

    manager.transport_factory = ConflictingBlock
    start(guard, document)
    assert wait_done(manager)["state"] == "failed"
    assert guard.store.get("proxy_binding") is None
    assert guard.store.rows("SELECT * FROM whitelist") == []
    assert len(guard.store.rows("SELECT * FROM blocks WHERE ended IS NULL")) == 1


def test_unsafe_storage_and_linked_key_are_rejected(tmp_path):
    directory = tmp_path / "credentials"
    _private_directory(directory)
    other = tmp_path / "outside.key"
    other.write_bytes(b"secret")
    (directory / "client.key").symlink_to(other)
    with pytest.raises(ValueError, match="links"):
        _read_private(directory / "client.key")
    with pytest.raises(ValueError, match="links"):
        _private_directory(directory / "client.key")
    if os.name != "nt":
        directory.chmod(0o755)
        with pytest.raises(ValueError, match="permissions"):
            _private_directory(directory)


def test_pairing_web_requires_session_and_csrf_and_preview_redacts_token(web, enrollment):
    client, dispatcher = web
    document, manager, _, _ = enrollment
    for operation in ("proxy-pair-preview", "proxy-pair-status", "proxy-pair"):
        assert client.post("/api/rpc", headers=ORIGIN, json={"op": operation}).status_code == 401
    csrf = login(client)
    preview = client.post("/api/rpc", headers=ORIGIN,
                          json={"op": "proxy-pair-preview", "args": {"document": document}})
    assert preview.status_code == 200 and document["token"] not in preview.text
    request = {"op": "proxy-pair", "args": {"document": document, "trusted_relay": RELAY}}
    assert client.post("/api/rpc", headers=ORIGIN, json=request).status_code == 401
    assert manager.status()["state"] == "idle"
    assert client.post("/api/rpc", headers=ORIGIN | {"x-csrf-token": csrf}, json=request).status_code == 200
    assert wait_done(manager)["state"] == "paired"
    assert document["token"] not in json.dumps(dispatcher.guard.store.rows("SELECT * FROM audit"))


def test_primary_ui_uses_file_preview_explicit_trust_and_honest_progress(web):
    client, _ = web
    login(client)
    script = client.get("/static/app.js").text
    assert "Подключить файлом" in script and "proxy-pair-preview" in script
    assert "trust_relay" in script and "trusted_relay:data.get" in script
    assert "Реальные IP: совпадений пока нет" in script
    assert "Ожидаем свежие события и сопоставления" in script
    assert "Ручная настройка" in script


def test_valid_certificate_from_wrong_ca_is_rejected(guard, enrollment, tmp_path):
    document, manager, transport, _ = enrollment
    from rdp_guard.proxy_pairing import SETTINGS
    other_dir = tmp_path / "other-authority"
    other_document = create_pairing(other_dir, {key: document[key] for key in SETTINGS})
    other = PairingAuthority(other_document, other_dir, lambda receipt: None)

    class WrongCA(transport):
        def enroll(self, computer, csr):
            receipt = other.handle(dict(pairing_id=other_document["pairing_id"], token=other_document["token"],
                                        computer=computer, csr_pem=csr))
            return receipt | {"pairing_id": document["pairing_id"]}

    manager.transport_factory = WrongCA
    start(guard, document)
    assert wait_done(manager)["state"] == "failed"
    assert guard.store.get("proxy_binding") is None
    other.close()


def test_shutdown_cancel_can_finish_without_accessing_closed_store(guard, enrollment):
    document, manager, transport, _ = enrollment
    entered, release = threading.Event(), threading.Event()

    class Slow(transport):
        def enroll(self, computer, csr):
            entered.set()
            assert release.wait(5)
            return super().enroll(computer, csr)

    manager.transport_factory = Slow
    start(guard, document)
    assert entered.wait(5)
    # Close concurrently: no Guard lock or Store operation is needed to cancel.
    closing = threading.Thread(target=manager.close)
    closing.start()
    assert manager._closed.wait(1)
    release.set()
    closing.join(5)
    assert not closing.is_alive()
    assert manager.status()["state"] == "cancelled"
    assert guard.store.get("proxy_binding") is None


@pytest.mark.windows
@pytest.mark.skipif(os.name != "nt" or os.environ.get("RDP_GUARD_NATIVE_TESTS") != "1",
                    reason="Requires elevated native Windows integration host")
def test_native_pairing_key_directory_is_private_before_key_is_written(tmp_path):
    import win32security
    from rdp_guard.proxy_enrollment import _write_once
    directory = tmp_path / "native-enrollment"
    _private_directory(directory)
    # Verify native pywin32 signatures, protected DACL and the SID set, then write.
    _windows_private(directory)
    path = directory / "client.key"
    assert not path.exists()
    _write_once(path, b"local credential ACL test; not a usable private key")
    descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                                                   win32security.DACL_SECURITY_INFORMATION)
    acl = descriptor.GetSecurityDescriptorDacl()
    assert acl is not None and acl.GetAceCount() == 2
    assert {win32security.ConvertSidToStringSid(acl.GetAce(index)[2]) for index in range(acl.GetAceCount())} == {
        "S-1-5-18", "S-1-5-32-544"}
    assert all(acl.GetAce(index)[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
               for index in range(acl.GetAceCount()))


def test_lost_completion_response_retries_same_ack_without_rolling_back_binding(guard, enrollment):
    document, manager, transport, sent = enrollment

    class LostAck(transport):
        acknowledgements = []

        def complete(self, computer, fingerprint):
            result = super().complete(computer, fingerprint)
            self.acknowledgements.append((computer, fingerprint))
            if len(self.acknowledgements) == 1:
                raise PairingRetryableError("durable ACK response lost")
            return result

    manager.transport_factory = LostAck
    start(guard, document)
    state = wait_done(manager)
    assert state["state"] == "paired" and state["handoff_pending"] is False
    assert len(LostAck.acknowledgements) == 2
    assert LostAck.acknowledgements[0] == LostAck.acknowledgements[1]
    assert len(sent) == 1 and guard.store.get("proxy_binding")["enabled"] is True


def test_enabled_identical_binding_recovers_ack_without_reenrollment_or_mode_change(guard, enrollment):
    document, manager, transport, sent = enrollment

    class BrokenAck(transport):
        def complete(self, computer, fingerprint):
            raise PairingError("permanent listener may already have taken over")

    manager.transport_factory = BrokenAck
    start(guard, document)
    state = wait_done(manager)
    assert state["state"] == "paired" and state["handoff_pending"] is True
    original = guard.store.get("proxy_binding") | {"mode": "enforce"}
    guard.store.set("proxy_binding", original)
    audit = guard.store.rows("SELECT * FROM audit")
    manager.transport_factory = transport
    start(guard, document)
    assert wait_done(manager)["handoff_pending"] is False
    assert len(sent) == 1  # Recovery uses local certificate, not the issuance endpoint.
    assert guard.store.get("proxy_binding") == original
    assert guard.store.rows("SELECT * FROM audit") == audit


def test_monotonic_expiry_after_issuance_prevents_late_guard_commit(guard, enrollment, monkeypatch):
    document, manager, transport, _ = enrollment
    import rdp_guard.proxy_enrollment as module
    monotonic = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: monotonic[0])

    class Late(transport):
        def enroll(self, computer, csr):
            receipt = super().enroll(computer, csr)
            monotonic[0] = 601.0
            return receipt

    manager.transport_factory = Late
    start(guard, document)
    assert wait_done(manager)["state"] == "failed"
    assert guard.store.get("proxy_binding") is None


def test_service_shutdown_rejects_new_pairing_before_creating_a_worker(guard, enrollment):
    document, manager, _, _ = enrollment
    guard.stopping = True
    with pytest.raises(ValueError, match="stopping"):
        start(guard, document)
    assert manager.status()["state"] == "idle"
    assert manager._thread is None
    assert guard.store.get("proxy_binding") is None
