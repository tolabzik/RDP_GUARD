"""Portable trust/identity tests and real loopback TLS enrollment checks."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
import socket
import ssl
import threading
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from rdp_guard import proxy_pairing as pairing


def settings():
    return dict(agent_url="https://127.0.0.1:9443", stream_id="rdp-45451", backend_id="windows",
                listener_ip="203.0.113.10", listener_port=45451,
                backend_ip="203.0.113.20", backend_port=45451,
                relay_ips=["203.0.113.10"], whitelist=["198.51.100.42/32"], protocols=["tcp"])


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    directory = tmp_path_factory.mktemp("proxy-pairing") / "keys"
    document = pairing.create_pairing(directory, settings(), allow_local_endpoint=True)
    return document, directory


@pytest.fixture(scope="module")
def client():
    return pairing.create_client_identity("WIN-TEST")


def envelope(document, csr, **updates):
    result = dict(pairing_id=document["pairing_id"], token=document["token"], computer="WIN-TEST", csr_pem=csr)
    result.update(updates)
    return result


def authority(bundle, callback=None, **kwargs):
    document, directory = bundle
    return pairing.PairingAuthority(document, directory, callback or (lambda _receipt: None),
                                    allow_local_endpoint=True, **kwargs)


@contextmanager
def live_server(bundle, callback=None):
    auth = authority(bundle, callback)
    server = pairing.make_pairing_server(auth, "127.0.0.1", 0)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    worker.start()
    document = deepcopy(bundle[0])
    document["agent_url"] = f"https://127.0.0.1:{server.server_port}"
    try:
        yield document, auth, server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        auth.close()


def test_invitation_contains_only_public_certificates_and_protected_files(bundle):
    document, directory = bundle
    assert set(document) == pairing.FIELDS
    assert "PRIVATE KEY" not in json.dumps(document)
    assert document["expires_at"] - document["issued_at"] == 600
    assert len(document["token"]) == 43
    assert set(path.name for path in directory.iterdir()) == {"ca.pem", "ca.key", "server.pem", "server.key"}
    cert = x509.load_pem_x509_certificate((directory / "server.pem").read_bytes())
    assert cert.fingerprint(hashes.SHA256()).hex() == document["server_sha256"]
    if os.name != "nt":
        assert directory.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir())


def test_existing_directory_never_overwritten(bundle):
    document, directory = bundle
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    with pytest.raises(FileExistsError):
        pairing.create_pairing(directory, settings(), allow_local_endpoint=True)
    assert before == {p.name: p.read_bytes() for p in directory.iterdir()}
    assert pairing.validate_pairing(document, allow_local_endpoint=True) == document


@pytest.mark.parametrize("field,value", [
    ("schema", "other"), ("stream_id", "../other"), ("backend_id", "a b"),
    ("pairing_id", str(uuid.uuid1())), ("token", "short"), ("token", "a" * 42 + "B"),
    ("server_sha256", "A" * 64), ("listener_port", True), ("backend_port", 0),
    ("relay_ips", []), ("relay_ips", ["0.0.0.0"]), ("whitelist", []),
    ("whitelist", ["0.0.0.0/0"]), ("protocols", ["tcp", "udp"]),
    ("issued_at", True), ("expires_at", float("nan")), ("ca_pem", "not a certificate"),
])
def test_strict_fields_reject_malformed_invitation(bundle, field, value):
    document = deepcopy(bundle[0])
    document[field] = value
    with pytest.raises(pairing.PairingError):
        pairing.validate_pairing(document, allow_local_endpoint=True)


@pytest.mark.parametrize("url", [
    "http://proxy.example:9443", "https://user:secret@proxy.example:9443",
    "https://proxy.example/path", "https://proxy.example/?secret=1", "https://proxy.example/#a",
    "https://proxy.example:0", "https://proxy.example:65536", "https://proxy.example\\@evil.example",
    "https://127.0.0.1", "https://[::1]", "https://[fe80::1]", "https://169.254.169.254",
    "https://224.0.0.1", "https://0.0.0.0", "https://localhost", "https://x.localhost",
])
def test_untrusted_origins_are_refused_by_default(bundle, url):
    document = deepcopy(bundle[0])
    document["agent_url"] = url
    with pytest.raises(pairing.PairingError):
        pairing.validate_pairing(document)


def test_document_bounds_unknown_fields_expiry_and_future_time(bundle):
    document = deepcopy(bundle[0])
    for changes in ({"extra": 1}, {"backend_id": "x" * pairing.MAX_DOCUMENT},
                    {"expires_at": document["issued_at"] + 601},
                    {"expires_at": time.time() - 1},
                    {"issued_at": time.time() + 30, "expires_at": time.time() + 600}):
        with pytest.raises(pairing.PairingError):
            pairing.validate_pairing(document | changes, allow_local_endpoint=True)


def test_one_identity_retry_returns_same_certificate_and_callback_once(bundle, client):
    receipts = []
    auth = authority(bundle, receipts.append)
    request = envelope(bundle[0], client[1])
    first = auth.handle(request)
    second = auth.handle(request)
    assert first == second == auth.enrolled
    assert receipts == [first]
    assert pairing.validate_client_certificate(first["client_pem"], client[0].encode(),
                                               bundle[0]["ca_pem"], "win-test") == first["client_sha256"]
    first["computer"] = "MUTATED"
    assert auth.enrolled["computer"] == "WIN-TEST"


def test_completion_requires_committed_identity_and_is_idempotent(bundle, client):
    auth = authority(bundle)
    document = bundle[0]
    completion = dict(pairing_id=document["pairing_id"], token=document["token"],
                      computer="WIN-TEST", client_sha256="0" * 64)
    with pytest.raises(pairing.PairingError, match="committed"):
        auth.complete(completion)
    receipt = auth.handle(envelope(document, client[1]))
    assert not auth.acknowledged
    completion["client_sha256"] = receipt["client_sha256"]
    for changes in ({"token": "x" * 43}, {"computer": "OTHER"}, {"client_sha256": "0" * 64},
                    {"pairing_id": str(uuid.uuid4())}, {"extra": True}):
        with pytest.raises(pairing.PairingError):
            auth.complete(completion | changes)
        assert not auth.acknowledged
    expected = dict(ok=True, pairing_id=document["pairing_id"], completed=True)
    assert auth.complete(completion) == auth.complete(completion) == expected
    assert auth.acknowledged


def test_expired_completion_never_acknowledges(bundle, client):
    now = time.time()
    clock, mono = [now], [100]
    document = deepcopy(bundle[0]) | {"issued_at": now, "expires_at": now + 10}
    auth = authority((document, bundle[1]), clock=lambda: clock[0], monotonic=lambda: mono[0])
    receipt = auth.handle(envelope(document, client[1]))
    clock[0] -= 4
    mono[0] += 11
    with pytest.raises(pairing.PairingError, match="expired"):
        auth.complete(dict(pairing_id=document["pairing_id"], token=document["token"],
                           computer="WIN-TEST", client_sha256=receipt["client_sha256"]))
    assert not auth.acknowledged


def test_conflicting_second_identity_and_wrong_authorization_are_denied(bundle, client):
    auth = authority(bundle)
    request = envelope(bundle[0], client[1])
    for changes in ({"token": "x" * 43}, {"pairing_id": str(uuid.uuid4())},
                    {"computer": "WIN-OTHER"}, {"computer": "A\nB"}, {"extra": 1}):
        with pytest.raises(pairing.PairingError):
            auth.handle(request | changes)
    auth.handle(request)
    _, another_csr = pairing.create_client_identity("WIN-TEST")
    with pytest.raises(pairing.PairingError, match="another identity"):
        auth.handle(envelope(bundle[0], another_csr))


def test_callback_failure_reserves_same_certificate_for_atomic_retry(bundle, client):
    attempts = []

    def install(receipt):
        attempts.append(receipt)
        if len(attempts) == 1:
            raise OSError("simulated write failure")

    auth = authority(bundle, install)
    request = envelope(bundle[0], client[1])
    with pytest.raises(pairing.PairingRetryableError):
        auth.handle(request)
    assert auth.enrolled is None
    receipt = auth.handle(request)
    assert attempts == [receipt, receipt]
    assert auth.handle(request) == receipt
    assert len(attempts) == 2


def test_parallel_retries_only_commit_once(bundle, client):
    receipts = []
    auth = authority(bundle, receipts.append)
    request = envelope(bundle[0], client[1])
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(lambda _: auth.handle(request), range(12)))
    assert len(receipts) == 1
    assert all(row == receipts[0] for row in responses)


def test_wall_and_monotonic_expiry_close_and_clock_rollback(bundle, client):
    now = time.time()
    clock, monotonic = [now], [50.0]
    document = deepcopy(bundle[0]) | {"issued_at": now, "expires_at": now + 10}
    auth = authority((document, bundle[1]), clock=lambda: clock[0], monotonic=lambda: monotonic[0])
    request = envelope(document, client[1])
    clock[0] = now - 4  # Still inside permitted clock tolerance; monotonic expiry must win.
    monotonic[0] = 61
    with pytest.raises(pairing.PairingError, match="expired"):
        auth.handle(request)
    assert auth.enrolled is None
    auth = authority((document, bundle[1]), clock=lambda: now, monotonic=lambda: 1)
    auth.close()
    with pytest.raises(pairing.PairingError, match="closed"):
        auth.handle(request)
    assert auth.ca_key is None and auth.document["token"] == ""


@pytest.mark.parametrize("profile", ["weak", "ca", "extra_name", "wrong_name", "bad_signature"])
def test_csr_proof_of_possession_and_extensions(bundle, profile):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024 if profile == "weak" else 2048)
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WIN-TEST")]))
    names = [x509.DNSName("WIN-OTHER" if profile == "wrong_name" else "WIN-TEST")]
    if profile == "extra_name":
        names.append(x509.DNSName("OTHER"))
    builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if profile == "ca":
        builder = builder.add_extension(x509.BasicConstraints(True, None), critical=True)
    csr = builder.sign(key, hashes.SHA256())
    if profile == "bad_signature":
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        der[-1] ^= 1
        csr = x509.load_der_x509_csr(bytes(der))
    with pytest.raises(pairing.PairingError):
        authority(bundle).handle(envelope(bundle[0], csr.public_bytes(serialization.Encoding.PEM).decode()))


def test_certificate_validation_rejects_wrong_key_identity_and_server_certificate(bundle, client):
    receipt = authority(bundle).handle(envelope(bundle[0], client[1]))
    other_key, _ = pairing.create_client_identity("WIN-TEST")
    for cert, key, computer in (
        (receipt["client_pem"], other_key, "WIN-TEST"),
        (receipt["client_pem"], client[0], "OTHER"),
        ((bundle[1] / "server.pem").read_bytes(), (bundle[1] / "server.key").read_bytes(), "WIN-TEST"),
    ):
        with pytest.raises(pairing.PairingError):
            pairing.validate_client_certificate(cert, key, bundle[0]["ca_pem"], computer)


@pytest.mark.parametrize("profile", ["ca", "expired", "server", "extra_san", "bad_signature"])
def test_signed_but_invalid_certificate_profile_rejected(bundle, client, profile):
    auth = authority(bundle)
    key = serialization.load_pem_private_key(client[0].encode(), None)
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(pairing._leaf_name("WIN-TEST"))
               .issuer_name(auth.ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=2))
               .not_valid_after(now - timedelta(days=1) if profile == "expired" else now + timedelta(days=1))
               .add_extension(x509.BasicConstraints(profile == "ca", None), critical=True)
               .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if profile == "server"
                                                     else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("WIN-TEST")] +
                              ([x509.DNSName("OTHER")] if profile == "extra_san" else [])), critical=False)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(auth.ca.public_key()), critical=False))
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if profile == "bad_signature" else auth.ca_key
    cert = builder.sign(signing_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    with pytest.raises(pairing.PairingError):
        pairing.validate_client_certificate(cert, client[0], bundle[0]["ca_pem"], "WIN-TEST")


def test_real_tls_enrollment_verifies_pin_and_client_identity(bundle, client, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    with live_server(bundle) as (document, auth, _):
        transport = pairing.PairingTransport(document, allow_local_endpoint=True)
        receipt = transport.enroll("win-test", client[1])
        assert auth.enrolled == receipt
        assert transport.enroll("WIN-TEST", client[1]) == receipt
        assert pairing.validate_client_certificate(receipt["client_pem"], client[0],
                                                   document["ca_pem"], "WIN-TEST") == receipt["client_sha256"]
        assert not auth.acknowledged
        assert transport.complete("WIN-TEST", receipt["client_sha256"]) == {
            "ok": True, "pairing_id": document["pairing_id"], "completed": True}
        assert auth.acknowledged


def test_real_tls_complete_rejects_wrong_identity_and_unissued_certificate(bundle, client):
    with live_server(bundle) as (document, auth, _):
        transport = pairing.PairingTransport(document, allow_local_endpoint=True)
        with pytest.raises(pairing.PairingError):
            transport.complete("WIN-TEST", "0" * 64)
        receipt = transport.enroll("WIN-TEST", client[1])
        with pytest.raises(pairing.PairingError):
            transport.complete("OTHER", receipt["client_sha256"])
        assert not auth.acknowledged
        transport.complete("WIN-TEST", receipt["client_sha256"])
        assert auth.acknowledged


def test_complete_also_verifies_pin_before_authorization(bundle, client):
    with live_server(bundle) as (document, auth, _):
        transport = pairing.PairingTransport(document, allow_local_endpoint=True)
        receipt = transport.enroll("WIN-TEST", client[1])
        transport.document["server_sha256"] = "0" * 64
        with pytest.raises(pairing.PairingError, match="fingerprint"):
            transport.complete("WIN-TEST", receipt["client_sha256"])
        assert not auth.acknowledged


def test_pin_failure_prevents_any_authorization_request(bundle, client):
    with live_server(bundle) as (document, auth, _):
        received = []
        original = auth.handle
        auth.handle = lambda payload: received.append(payload) or original(payload)
        document["server_sha256"] = "0" * 64
        with pytest.raises(pairing.PairingError, match="fingerprint"):
            pairing.PairingTransport(document, allow_local_endpoint=True).enroll("WIN-TEST", client[1])
        assert received == [] and auth.enrolled is None


def test_hostname_mismatch_prevents_authorization_request(bundle, client):
    with live_server(bundle) as (document, auth, server):
        received = []
        auth.handle = lambda payload: received.append(payload)
        document["agent_url"] = f"https://localhost:{server.server_port}"
        with pytest.raises(pairing.PairingError, match="hostname"):
            pairing.PairingTransport(document, allow_local_endpoint=True).enroll("WIN-TEST", client[1])
        assert received == []


def test_real_tls_callback_failure_can_retry_same_identity(bundle, client):
    attempts = []

    def install(receipt):
        attempts.append(receipt)
        if len(attempts) == 1:
            raise OSError("test failure")

    with live_server(bundle, install) as (document, _, _):
        transport = pairing.PairingTransport(document, allow_local_endpoint=True)
        with pytest.raises(pairing.PairingRetryableError):
            transport.enroll("WIN-TEST", client[1])
        receipt = transport.enroll("WIN-TEST", client[1])
        assert attempts == [receipt, receipt]


def test_dns_loopback_and_mixed_resolution_are_rejected_before_connection(bundle, client):
    document = deepcopy(bundle[0]) | {"agent_url": "https://proxy.example:9443"}
    for rows in ([socket.getaddrinfo("127.0.0.1", 9443, type=socket.SOCK_STREAM)[0]],
                 [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.1", 9443)),
                  (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", 9443))]):
        transport = pairing.PairingTransport(document, resolver=lambda *_args, **_kw: rows)
        with pytest.raises(pairing.PairingError, match="concrete unicast"):
            transport.enroll("WIN-TEST", client[1])


def test_dns_deadline_retries_reuse_single_outstanding_resolver(bundle, client):
    release, calls = threading.Event(), []

    def resolve(*_args, **_kwargs):
        calls.append(True)
        release.wait(2)
        return socket.getaddrinfo("127.0.0.1", 9443, type=socket.SOCK_STREAM)

    transport = pairing.PairingTransport(bundle[0], timeout=0.03, resolver=resolve, allow_local_endpoint=True)
    try:
        for _ in range(2):
            started = time.monotonic()
            with pytest.raises(pairing.PairingRetryableError, match="DNS"):
                transport.enroll("WIN-TEST", client[1])
            assert time.monotonic() - started < 1
        assert len(calls) == 1
    finally:
        release.set()


def test_http_strict_framing_duplicate_fields_and_only_pair_endpoint(bundle, client):
    with live_server(bundle) as (document, auth, server):
        context = ssl.create_default_context(cadata=document["ca_pem"])
        body = json.dumps(envelope(document, client[1]))
        for path, payload, content_type in (
            ("/v1/ban", body, "application/json"),
            ("/v1/pair", body[:-1] + ',"token":"other"}', "application/json"),
            ("/v1/pair", body, "text/plain"),
            ("/v1/pair", "x" * (pairing.MAX_DOCUMENT + 1), "application/json"),
        ):
            connection = http.client.HTTPSConnection("127.0.0.1", server.server_port, context=context, timeout=2)
            try:
                connection.request("POST", path, payload, {"Content-Type": content_type})
                response = connection.getresponse()
                assert response.status in (400, 404)
                assert document["token"].encode() not in response.read()
            finally:
                connection.close()
        assert auth.enrolled is None


def test_short_request_deadline_closes_slow_body(bundle, monkeypatch):
    monkeypatch.setattr(pairing, "REQUEST_SECONDS", 0.15)
    with live_server(bundle) as (document, auth, server):
        context = ssl.create_default_context(cadata=document["ca_pem"])
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
                started = time.monotonic()
                sock.sendall(b"POST /v1/pair HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
                assert sock.recv(10) == b""
                assert time.monotonic() - started < 1
        assert auth.enrolled is None


def test_client_certificate_der_pin_is_not_pem_hash(bundle, client):
    receipt = authority(bundle).handle(envelope(bundle[0], client[1]))
    cert = x509.load_pem_x509_certificate(receipt["client_pem"].encode())
    assert hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest() == receipt["client_sha256"]
    assert hashlib.sha256(receipt["client_pem"].encode()).hexdigest() != receipt["client_sha256"]
