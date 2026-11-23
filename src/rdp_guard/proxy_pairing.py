"""Short-lived, one-use certificate enrollment for one proxy stream.

The .rdpg file is a bearer invitation: transfer it over a trusted channel. It
contains no private key. Server TLS is CA/hostname verified and DER-pinned before
the token is transmitted. The enrollment endpoint is temporary and independent
of the permanent client-certificate-required evidence service.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import math
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from .models import network


SCHEMA = "rdpguard.proxy-pairing.v1"
MAX_DOCUMENT = 64 * 1024
MAX_PEM = 16 * 1024
MAX_LIFETIME = 600
HANDSHAKE_SECONDS = 5
REQUEST_SECONDS = 10
SETTINGS = {"agent_url", "stream_id", "backend_id", "listener_ip", "listener_port", "backend_ip",
            "backend_port", "relay_ips", "whitelist", "protocols"}
FIELDS = SETTINGS | {"schema", "ca_pem", "server_sha256", "pairing_id", "token", "issued_at", "expires_at"}
RECEIPT_FIELDS = {"ok", "pairing_id", "computer", "client_pem", "client_sha256", "stream_id", "backend_id"}
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
COMPUTER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}\Z")
DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


class PairingError(ValueError):
    """Permanent validation/trust/authorization rejection; do not retry blindly."""


class PairingRetryableError(ConnectionError):
    """Temporary transport or installation failure; retry the identical CSR."""


def _json_bytes(value):
    try:
        data = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise PairingError("Invalid pairing JSON") from exc
    if len(data) > MAX_DOCUMENT:
        raise PairingError("Pairing document exceeds 64 KiB")
    return data


def _no_duplicate_keys(items):
    result = {}
    for key, value in items:
        if key in result:
            raise PairingError("Duplicate JSON field")
        result[key] = value
    return result


def _number(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise PairingError("Expected a finite timestamp")
    return float(value)


def _lifetime(document, now):
    issued, expires = _number(document["issued_at"]), _number(document["expires_at"])
    if not 0 < expires - issued <= MAX_LIFETIME or issued > now + 5 or expires <= now:
        raise PairingError("Pairing invitation is expired or has an invalid lifetime")


def _address(value, *, allow_local=False):
    if not isinstance(value, str) or "%" in value:
        raise PairingError("Expected a literal IP without a scope identifier")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PairingError("Invalid IP address") from exc
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if (ip.is_unspecified or ip.is_multicast or ip.is_link_local or str(ip) == "255.255.255.255"
            or (ip.is_loopback and not allow_local)):
        raise PairingError("Pairing endpoint must use a concrete unicast address")
    return str(ip)


def _origin(value, *, allow_local=False):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise PairingError("Invalid HTTPS origin")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment or not 1 <= (443 if parsed.port is None else parsed.port) <= 65535):
            raise ValueError
        host = parsed.hostname.lower()
        if "%" in host:
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if (len(host) > 253 or not all(DNS_LABEL.fullmatch(label) for label in host.split("."))
                    or (not allow_local and (host == "localhost" or host.endswith(".localhost")))):
                raise ValueError
        else:
            host = _address(host, allow_local=allow_local)
        origin_host = f"[{host}]" if ":" in host else host
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"https://{origin_host}{port}"
    except (ValueError, TypeError) as exc:
        raise PairingError("Expected an HTTPS origin without credentials, path, query or fragment") from exc


def _computer(value):
    if not isinstance(value, str) or not COMPUTER.fullmatch(value):
        raise PairingError("Invalid native Windows computer name")
    return value.upper()


def _pem(value, label):
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeError as exc:
            raise PairingError("PEM must be ASCII") from exc
    if not isinstance(value, str) or len(value) > MAX_PEM:
        raise PairingError("Invalid PEM document")
    try:
        value = value.replace("\r\n", "\n").strip() + "\n"
        data = value.encode("ascii")
    except UnicodeError as exc:
        raise PairingError("PEM must be ASCII") from exc
    if (not data.startswith(f"-----BEGIN {label}-----\n".encode())
            or not data.endswith(f"-----END {label}-----\n".encode())
            or data.count(b"-----BEGIN ") != 1 or data.count(b"-----END ") != 1):
        raise PairingError("Expected exactly one PEM object")
    return data


def _rsa_key(key):
    if not isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)) or not 2048 <= key.key_size <= 8192:
        raise PairingError("RSA key size must be between 2048 and 8192 bits")
    public = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    if public.public_numbers().e != 65537:
        raise PairingError("Unsupported RSA public exponent")
    return key


def _verify_signature(cert, public):
    _rsa_key(public)
    if cert.signature_hash_algorithm.name not in ("sha256", "sha384", "sha512"):
        raise PairingError("Weak certificate signature")
    try:
        public.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise PairingError("Certificate signature is invalid") from exc


def _valid_now(cert, now):
    instant = datetime.fromtimestamp(now, timezone.utc)
    if not cert.not_valid_before_utc <= instant < cert.not_valid_after_utc:
        raise PairingError("Certificate is not currently valid")


def _ca(value, now):
    try:
        cert = x509.load_pem_x509_certificate(_pem(value, "CERTIFICATE"))
        _valid_now(cert, now)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if (cert.subject != cert.issuer or not bc.critical or not bc.value.ca
                or bc.value.path_length != 0 or not ku.critical or not ku.value.key_cert_sign):
            raise PairingError("Invalid dedicated pairing CA")
        _verify_signature(cert, cert.public_key())
        return cert
    except (ValueError, x509.ExtensionNotFound, x509.DuplicateExtension) as exc:
        raise PairingError("Invalid pairing CA certificate") from exc


def validate_pairing(document, now=None, *, allow_local_endpoint=False):
    """Pure strict validation. DNS is checked by transport before connecting."""
    now = time.time() if now is None else _number(now)
    if not isinstance(document, dict) or set(document) != FIELDS or document.get("schema") != SCHEMA:
        raise PairingError("Unknown or missing pairing document fields")
    _json_bytes(document)
    result = deepcopy(document)
    _lifetime(result, now)
    result["agent_url"] = _origin(result["agent_url"], allow_local=allow_local_endpoint)
    for field in ("stream_id", "backend_id"):
        if not isinstance(result[field], str) or not SLUG.fullmatch(result[field]):
            raise PairingError("Invalid stream/backend identity")
    try:
        identity = uuid.UUID(result["pairing_id"])
        if not identity.int or identity.version != 4 or str(identity) != result["pairing_id"]:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise PairingError("Invalid pairing UUID") from exc
    token = result["token"]
    if (not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
            or len(base64.urlsafe_b64decode(token + "=")) != 32
            or base64.urlsafe_b64encode(base64.urlsafe_b64decode(token + "=")).decode().rstrip("=") != token):
        raise PairingError("Invalid one-use pairing token")
    if not isinstance(result["server_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", result["server_sha256"]):
        raise PairingError("Invalid TLS server fingerprint")
    cert = _ca(result["ca_pem"], now)
    result["ca_pem"] = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    for field in ("listener_ip", "backend_ip"):
        result[field] = _address(result[field], allow_local=allow_local_endpoint)
    for field in ("listener_port", "backend_port"):
        if type(result[field]) is not int or not 1 <= result[field] <= 65535:
            raise PairingError("Invalid stream/backend port")
    if not isinstance(result["relay_ips"], list) or not 1 <= len(result["relay_ips"]) <= 16:
        raise PairingError("Expected 1 to 16 shared relay IPs")
    result["relay_ips"] = sorted({_address(ip, allow_local=allow_local_endpoint) for ip in result["relay_ips"]})
    if not isinstance(result["whitelist"], list) or not 1 <= len(result["whitelist"]) <= 1000:
        raise PairingError("At least one administrator network is required")
    try:
        result["whitelist"] = sorted({network(value) for value in result["whitelist"]})
    except (ValueError, TypeError) as exc:
        raise PairingError("Invalid administrator network") from exc
    if result["protocols"] != ["tcp"]:
        raise PairingError("Pairing v1 supports an explicitly published TCP stream")
    return result


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")


def _leaf_name(computer):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                        computer if len(computer) <= 64 else "RDP Guard Windows client")])


def _leaf(builder, public, issuer, issuer_key, now, eku, subject, san):
    begin = datetime.fromtimestamp(now, timezone.utc) - timedelta(minutes=5)
    return (builder.subject_name(subject).issuer_name(issuer.subject).public_key(public)
            .serial_number(x509.random_serial_number()).not_valid_before(begin)
            .not_valid_after(min(begin + timedelta(days=365), issuer.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
            .sign(issuer_key, hashes.SHA256()))


def create_pairing(directory: Path, settings: dict, now=None, *, allow_local_endpoint=False):
    """Create a fresh protected key directory; caller writes/transfers the .rdpg."""
    now = time.time() if now is None else _number(now)
    if not isinstance(settings, dict) or set(settings) - SETTINGS - {"lifetime_seconds"} or SETTINGS - set(settings):
        raise PairingError("Unknown or missing pairing settings")
    lifetime = settings.get("lifetime_seconds", MAX_LIFETIME)
    if type(lifetime) is not int or not 1 <= lifetime <= MAX_LIFETIME:
        raise PairingError("Pairing lifetime must be 1 to 600 seconds")
    origin = _origin(settings["agent_url"], allow_local=allow_local_endpoint)
    pair_id = str(uuid.uuid4())
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    begin = datetime.fromtimestamp(now, timezone.utc) - timedelta(minutes=5)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RDP Guard pairing CA " + pair_id[:8])])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(begin)
          .not_valid_after(begin + timedelta(days=730))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host = urlsplit(origin).hostname
    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    server = _leaf(x509.CertificateBuilder(), server_key.public_key(), ca, ca_key, now,
                   ExtendedKeyUsageOID.SERVER_AUTH,
                   x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RDP Guard proxy")]), san)
    document = {key: deepcopy(settings[key]) for key in SETTINGS}
    document.update(schema=SCHEMA, agent_url=origin, pairing_id=pair_id, token=secrets.token_urlsafe(32),
                    issued_at=now, expires_at=now + lifetime,
                    ca_pem=ca.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                    server_sha256=server.fingerprint(hashes.SHA256()).hex())
    document = validate_pairing(document, now, allow_local_endpoint=allow_local_endpoint)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    written = []
    try:
        for name, value in {"ca.pem": document["ca_pem"], "ca.key": _key_pem(ca_key),
                            "server.pem": server.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                            "server.key": _key_pem(server_key)}.items():
            path = directory / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(path, flags, 0o600), "w", encoding="ascii", newline="\n") as out:
                written.append(path)
                out.write(value)
                out.flush()
                os.fsync(out.fileno())
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        directory.rmdir()
        raise
    return document


def create_client_identity(computer):
    computer = _computer(computer)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder().subject_name(_leaf_name(computer))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(computer)]), critical=False)
           .sign(key, hashes.SHA256()))
    return _key_pem(key), csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _csr(value, computer):
    try:
        csr = x509.load_pem_x509_csr(_pem(value, "CERTIFICATE REQUEST"))
        _rsa_key(csr.public_key())
        if not csr.is_signature_valid or csr.signature_hash_algorithm.name not in ("sha256", "sha384", "sha512"):
            raise PairingError("Invalid CSR proof of possession")
        if csr.subject != _leaf_name(computer) or len(csr.extensions) != 1:
            raise PairingError("CSR identity/extensions do not match the requested computer")
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        if san.critical or list(san.value) != [x509.DNSName(computer)]:
            raise PairingError("CSR names do not match the requested computer")
        if any(attribute.oid.dotted_string != "1.2.840.113549.1.9.14" for attribute in csr.attributes):
            raise PairingError("Unsupported CSR attributes")
        return csr
    except (ValueError, x509.ExtensionNotFound, x509.DuplicateExtension) as exc:
        raise PairingError("Invalid enrollment CSR") from exc


def validate_client_certificate(cert_pem, key_pem, ca_pem, computer):
    """Validate issuance, identity, least-privilege profile and local key match."""
    computer, now = _computer(computer), time.time()
    try:
        ca = _ca(ca_pem, now)
        cert = x509.load_pem_x509_certificate(_pem(cert_pem, "CERTIFICATE"))
        key = serialization.load_pem_private_key(_pem(key_pem, "PRIVATE KEY"), password=None)
        _rsa_key(key)
        _rsa_key(cert.public_key())
        _valid_now(cert, now)
        if cert.issuer != ca.subject or cert.subject != _leaf_name(computer):
            raise PairingError("Client certificate identity or issuer mismatch")
        _verify_signature(cert, ca.public_key())
        if cert.public_key().public_numbers() != key.public_key().public_numbers():
            raise PairingError("Client certificate does not match the local private key")
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        if (not bc.critical or bc.value.ca or not ku.critical or not ku.value.digital_signature
                or not ku.value.key_encipherment or ku.value.content_commitment or ku.value.data_encipherment
                or ku.value.key_cert_sign or ku.value.crl_sign or ku.value.key_agreement
                or eku.critical or san.critical or ski.critical or aki.critical
                or list(eku.value) != [ExtendedKeyUsageOID.CLIENT_AUTH]
                or list(san.value) != [x509.DNSName(computer)]
                or ski.value != x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
                or aki.value != x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key())
                or {ext.oid for ext in cert.extensions} != {
                    ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
                    ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER}):
            raise PairingError("Invalid client certificate privileges or names")
        return cert.fingerprint(hashes.SHA256()).hex()
    except (ValueError, TypeError, x509.ExtensionNotFound, x509.DuplicateExtension) as exc:
        raise PairingError("Client certificate validation failed") from exc


class PairingAuthority:
    def __init__(self, document, directory, on_enrolled, clock=time.time, *, monotonic=time.monotonic,
                 allow_local_endpoint=False):
        self.clock, self.monotonic = clock, monotonic
        self.document = validate_pairing(document, clock(), allow_local_endpoint=allow_local_endpoint)
        self.directory, self.on_enrolled = Path(directory), on_enrolled
        self.deadline = monotonic() + self.document["expires_at"] - clock()
        self.lock = threading.RLock()
        self._closed, self._committed, self._receipt, self._request_id = False, False, None, None
        self._acknowledged = False
        self.ca = _ca(self.document["ca_pem"], clock())
        key_path = self.directory / "ca.key"
        if key_path.is_symlink() or key_path.stat().st_size > MAX_PEM:
            raise PairingError("Invalid authority key file")
        self.ca_key = serialization.load_pem_private_key(_pem(key_path.read_text("ascii"), "PRIVATE KEY"), None)
        _rsa_key(self.ca_key)
        if self.ca_key.public_key().public_numbers() != self.ca.public_key().public_numbers():
            raise PairingError("Authority key does not match invitation CA")
        server = x509.load_pem_x509_certificate(_pem((self.directory / "server.pem").read_text("ascii"), "CERTIFICATE"))
        if not hmac.compare_digest(server.fingerprint(hashes.SHA256()).hex(), self.document["server_sha256"]):
            raise PairingError("Authority TLS certificate does not match invitation")

    @property
    def enrolled(self):
        with self.lock:
            return deepcopy(self._receipt) if self._committed else None

    @property
    def acknowledged(self):
        """Windows has durably saved its credentials and monitor binding."""
        with self.lock:
            return self._acknowledged

    def handle(self, envelope):
        with self.lock:
            if self._closed or self.monotonic() >= self.deadline:
                raise PairingError("Pairing invitation expired or closed")
            _lifetime(self.document, self.clock())
            if not isinstance(envelope, dict) or set(envelope) != {"pairing_id", "token", "computer", "csr_pem"}:
                raise PairingError("Unknown enrollment fields")
            _json_bytes(envelope)
            token = envelope["token"]
            if (not isinstance(token, str) or not token.isascii()
                    or not hmac.compare_digest(token, self.document["token"])
                    or envelope["pairing_id"] != self.document["pairing_id"]):
                raise PairingError("Enrollment authorization denied")
            computer = _computer(envelope["computer"])
            csr = _csr(envelope["csr_pem"], computer)
            request_id = hashlib.sha256(computer.encode() + csr.public_bytes(serialization.Encoding.DER)).hexdigest()
            if self._request_id is not None and request_id != self._request_id:
                raise PairingError("Pairing invitation was already reserved for another identity")
            if self._receipt is None:
                cert = _leaf(x509.CertificateBuilder(), csr.public_key(), self.ca, self.ca_key, self.clock(),
                             ExtendedKeyUsageOID.CLIENT_AUTH, _leaf_name(computer), x509.DNSName(computer))
                self._request_id = request_id
                self._receipt = dict(ok=True, pairing_id=self.document["pairing_id"], computer=computer,
                                     client_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                                     client_sha256=cert.fingerprint(hashes.SHA256()).hex(),
                                     stream_id=self.document["stream_id"], backend_id=self.document["backend_id"])
            if not self._committed:
                try:
                    self.on_enrolled(deepcopy(self._receipt))
                except Exception as exc:
                    raise PairingRetryableError("Enrollment installation did not complete; retry identical identity") from exc
                self._committed = True
            return deepcopy(self._receipt)

    def complete(self, envelope):
        """An explicit final ACK prevents switching services before receipt delivery."""
        with self.lock:
            if self._closed or self.monotonic() >= self.deadline:
                raise PairingError("Pairing invitation expired or closed")
            _lifetime(self.document, self.clock())
            if (not isinstance(envelope, dict)
                    or set(envelope) != {"pairing_id", "token", "computer", "client_sha256"}):
                raise PairingError("Unknown enrollment completion fields")
            _json_bytes(envelope)
            token = envelope["token"]
            if (not isinstance(token, str) or not token.isascii()
                    or not hmac.compare_digest(token, self.document["token"])
                    or envelope["pairing_id"] != self.document["pairing_id"]):
                raise PairingError("Enrollment authorization denied")
            computer = _computer(envelope["computer"])
            fingerprint = envelope["client_sha256"]
            if (not self._committed or not isinstance(fingerprint, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", fingerprint)
                    or computer != self._receipt["computer"]
                    or not hmac.compare_digest(fingerprint, self._receipt["client_sha256"])):
                raise PairingError("Completion does not match committed enrollment")
            self._acknowledged = True
            return dict(ok=True, pairing_id=self.document["pairing_id"], completed=True)

    def close(self):
        """Withdraw enrollment; setup owns deletion of invitation/CA key files."""
        with self.lock:
            self._closed = True
            self.document["token"] = ""
            self.ca_key = None


def _close_socket(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def make_pairing_server(authority, bind_host, bind_port):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            try:
                if self.path not in ("/v1/pair", "/v1/pair/complete"):
                    self.send_error(404)
                    return
                if (self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1
                        or len(self.headers.get_all("Content-Type", [])) != 1
                        or self.headers["Content-Type"].split(";")[0] != "application/json"):
                    raise PairingError("Invalid request framing")
                length = self.headers["Content-Length"]
                if not re.fullmatch(r"[0-9]{1,6}", length) or not 0 < int(length) <= MAX_DOCUMENT:
                    raise PairingError("Invalid body size")
                data = self.rfile.read(int(length))
                if len(data) != int(length):
                    raise PairingError("Incomplete request")
                envelope = json.loads(data, object_pairs_hook=_no_duplicate_keys)
                operation = authority.handle if self.path == "/v1/pair" else authority.complete
                receipt, code = operation(envelope), 200
            except PairingRetryableError:
                receipt, code = {"error": "Enrollment temporarily unavailable; retry the same identity"}, 503
            except (PairingError, ValueError, TypeError, KeyError, UnicodeError):
                receipt, code = {"error": "Enrollment validation or authorization failed"}, 400
            except Exception:
                receipt, code = {"error": "Enrollment unavailable"}, 503
            data = _json_bytes(receipt)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

    class Server(HTTPServer):
        address_family = socket.AF_INET6 if ipaddress.ip_address(bind_host).version == 6 else socket.AF_INET

        def get_request(self):
            raw, peer = super().get_request()
            sock = None
            try:
                raw.settimeout(HANDSHAKE_SECONDS)
                sock = self.tls.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
                timer = threading.Timer(HANDSHAKE_SECONDS, _close_socket, (sock,))
                timer.daemon = True
                timer.start()
                try:
                    sock.do_handshake()
                finally:
                    timer.cancel()
                return sock, peer
            except BaseException:
                (sock or raw).close()
                raise

        def finish_request(self, request, client_address):
            timer = threading.Timer(REQUEST_SECONDS, _close_socket, (request,))
            timer.daemon = True
            timer.start()
            try:
                super().finish_request(request, client_address)
            finally:
                timer.cancel()

        def handle_error(self, *_args):
            pass  # Never log enrollment payloads, token, CSR, or private material.

    server = Server((bind_host, bind_port), Handler, bind_and_activate=False)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(authority.directory / "server.pem"), str(authority.directory / "server.key"))
        server.tls = context
        server.timeout = 1
        server.server_bind()
        server.server_activate()
        return server
    except BaseException:
        server.server_close()
        raise


class PairingTransport:
    def __init__(self, document, *, timeout=5, clock=time.time, monotonic=time.monotonic,
                 allow_local_endpoint=False, resolver=socket.getaddrinfo):
        if type(timeout) not in (int, float) or not 0 < timeout <= 5:
            raise PairingError("Pairing timeout must be at most five seconds")
        self.document = validate_pairing(document, clock(), allow_local_endpoint=allow_local_endpoint)
        self.clock, self.monotonic, self.timeout, self.resolver = clock, monotonic, timeout, resolver
        self.allow_local_endpoint = allow_local_endpoint
        self.deadline = monotonic() + self.document["expires_at"] - clock()
        self._dns = None

    def _resolve(self, host, port, deadline):
        # One daemon resolver per transport, reused on timeout retries. DNS cannot
        # block a Windows worker indefinitely or cause unbounded retry threads.
        if self._dns is None:
            result = queue.Queue(maxsize=1)
            self._dns = result

            def resolve():
                try:
                    result.put(self.resolver(host, port, type=socket.SOCK_STREAM))
                except Exception as exc:
                    result.put(exc)

            threading.Thread(target=resolve, name="rdpguard-pair-dns", daemon=True).start()
        try:
            rows = self._dns.get(timeout=max(0.001, deadline - self.monotonic()))
        except queue.Empty as exc:
            raise PairingRetryableError("Pairing DNS resolution timed out") from exc
        self._dns = None
        if isinstance(rows, Exception):
            raise PairingRetryableError("Pairing DNS resolution failed") from rows
        if not rows or len(rows) > 64:
            raise PairingError("Invalid endpoint resolution")
        endpoints = []
        for family, kind, protocol, _, address in rows:
            if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM:
                continue
            _address(address[0], allow_local=self.allow_local_endpoint)
            endpoints.append((family, protocol, address))
        if not endpoints:
            raise PairingError("Endpoint has no approved address")
        return endpoints

    def _request(self, endpoint, payload):
        document = self.document
        _lifetime(document, self.clock())
        if self.monotonic() >= self.deadline:
            raise PairingError("Pairing invitation expired")
        if endpoint not in ("/v1/pair", "/v1/pair/complete"):
            raise PairingError("Unsupported enrollment endpoint")
        body = _json_bytes(payload)
        origin = urlsplit(document["agent_url"])
        deadline = min(self.deadline, self.monotonic() + self.timeout)
        endpoints = self._resolve(origin.hostname, origin.port or 443, deadline)
        context = ssl.create_default_context(cadata=document["ca_pem"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        connection = http.client.HTTPSConnection(origin.hostname, origin.port or 443,
                                                  timeout=self.timeout, context=context)
        sock, timer = None, None
        try:
            last_error = None
            for family, protocol, socket_address in endpoints:
                if self.monotonic() >= deadline:
                    break
                raw = socket.socket(family, socket.SOCK_STREAM, protocol)
                try:
                    raw.settimeout(max(0.001, deadline - self.monotonic()))
                    raw.connect(socket_address)
                    raw.settimeout(max(0.001, deadline - self.monotonic()))
                    sock = context.wrap_socket(raw, server_hostname=origin.hostname)
                    break
                except ssl.SSLCertVerificationError as exc:
                    raw.close()
                    raise PairingError("Pairing TLS certificate or hostname verification failed") from exc
                except (OSError, ssl.SSLError) as exc:
                    raw.close()
                    last_error = exc
            if sock is None:
                raise PairingRetryableError("Pairing connection failed or timed out") from last_error
            if not hmac.compare_digest(hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest(),
                                       document["server_sha256"]):
                raise PairingError("Pairing server certificate fingerprint mismatch")
            if self.monotonic() >= deadline:
                raise PairingRetryableError("Pairing deadline expired before authorization")
            # Supplying the already-verified socket prevents a second DNS lookup
            # or connection between verification and transmission of the token.
            connection.sock = sock
            timer = threading.Timer(max(0.001, deadline - self.monotonic()), _close_socket, (sock,))
            timer.daemon = True
            timer.start()
            connection.request("POST", endpoint, body=body, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status >= 500:
                raise PairingRetryableError("Pairing installation is temporarily unavailable")
            if response.status != 200:  # Includes redirects, which are never followed.
                raise PairingError("Pairing request was rejected")
            content = response.read(MAX_DOCUMENT + 1)
            if len(content) > MAX_DOCUMENT:
                raise PairingError("Pairing response exceeds size limit")
            return json.loads(content, object_pairs_hook=_no_duplicate_keys)
        except PairingError:
            raise
        except PairingRetryableError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise PairingRetryableError("Pairing transport failed; retry the identical identity") from exc
        except (ValueError, TypeError, KeyError) as exc:
            raise PairingError("Invalid pairing response") from exc
        finally:
            if timer is not None:
                timer.cancel()
            if sock is not None:
                _close_socket(sock)
            connection.close()

    def enroll(self, computer, csr_pem):
        computer = _computer(computer)
        _csr(csr_pem, computer)
        document = self.document
        receipt = self._request("/v1/pair", dict(pairing_id=document["pairing_id"], token=document["token"],
                                               computer=computer, csr_pem=csr_pem))
        if (not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS or receipt.get("ok") is not True
                or any(receipt.get(k) != document[k] for k in ("pairing_id", "stream_id", "backend_id"))
                or receipt.get("computer") != computer
                or not isinstance(receipt.get("client_sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", receipt["client_sha256"])):
            raise PairingError("Enrollment receipt does not match the invitation")
        try:
            cert = x509.load_pem_x509_certificate(_pem(receipt["client_pem"], "CERTIFICATE"))
        except (ValueError, TypeError) as exc:
            raise PairingError("Invalid enrollment certificate") from exc
        if cert.fingerprint(hashes.SHA256()).hex() != receipt["client_sha256"]:
            raise PairingError("Enrollment certificate fingerprint mismatch")
        return receipt

    def complete(self, computer, client_sha256):
        """Call only after Windows durably commits its local identity and binding.

        A lost ACK response does not invalidate that durable Windows binding: the
        setup server may already have switched to the permanent mTLS service.
        """
        computer = _computer(computer)
        if not isinstance(client_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", client_sha256):
            raise PairingError("Invalid enrolled client certificate fingerprint")
        document = self.document
        receipt = self._request("/v1/pair/complete", dict(pairing_id=document["pairing_id"], token=document["token"],
                               computer=computer, client_sha256=client_sha256))
        if (not isinstance(receipt, dict) or set(receipt) != {"ok", "pairing_id", "completed"}
                or receipt.get("ok") is not True or receipt.get("completed") is not True
                or receipt.get("pairing_id") != document["pairing_id"]):
            raise PairingError("Enrollment completion receipt does not match the invitation")
        return receipt
