"""Local-key, asynchronous enrollment from a short-lived .rdpg pairing file."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import threading
import time
import uuid

from .models import address, contains
from .proxy_client import validate_binding
from .proxy_pairing import (PairingError, PairingRetryableError, PairingTransport,
                            create_client_identity, validate_client_certificate, validate_pairing)


MAX_FILE = 65536


def native_computer():
    """Use the same native identity that the event exporter sends to Linux."""
    if os.name == "nt":
        try:
            from .windows.proxy_export import NativeProxyExporter, _system
            records = NativeProxyExporter()._query("*", 1)
            if records:
                return _computer(_system(records[0])[2]["computer"])
        except Exception:
            pass
        try:
            import win32api
            # COMPUTER_NAME_FORMAT.ComputerNamePhysicalDnsFullyQualified.
            return _computer(win32api.GetComputerNameEx(7))
        except Exception:
            pass
    return _computer(platform.node())


def _computer(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", value):
        raise ValueError("Native Windows computer name is unavailable")
    return value.rstrip(".").upper()


def _no_links(path):
    for item in (path, *path.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("Enrollment storage cannot contain links")
        # Python versions without Path.is_junction still expose Windows reparse attributes.
        if item.exists() and getattr(item.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Enrollment storage cannot contain reparse points")


def _windows_private(path, *, create=False, directory=True):
    import pywintypes
    import win32api
    import win32file
    import win32security
    if create:
        attributes = pywintypes.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1)
        win32file.CreateDirectory(str(path), attributes)
    descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
    trusted_owners = {"S-1-5-18", "S-1-5-32-544"}
    administrators = win32security.ConvertStringSidToSid("S-1-5-32-544")
    if win32security.CheckTokenMembership(None, administrators):
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 0x0008)  # TOKEN_QUERY
        try:
            trusted_owners.add(win32security.ConvertSidToStringSid(
                win32security.GetTokenInformation(token, win32security.TokenUser)[0]))
        finally:
            token.Close()
    if win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in trusted_owners:
        raise ValueError("Enrollment storage is owned by an untrusted principal")
    acl = descriptor.GetSecurityDescriptorDacl()
    if (acl is None or acl.GetAceCount() != 2
            or (directory and not descriptor.GetSecurityDescriptorControl()[0] & 0x1000)):
        raise ValueError("Enrollment directory permissions are not private")
    allowed = set()
    for index in range(acl.GetAceCount()):
        header, mask, sid = acl.GetAce(index)
        if (header[0] != win32security.ACCESS_ALLOWED_ACE_TYPE or mask & 0x1F01FF != 0x1F01FF
                or (directory and (header[1] & 0x03 != 0x03 or header[1] & 0x08))):
            raise ValueError("Enrollment directory permissions are not private")
        allowed.add(win32security.ConvertSidToStringSid(sid))
    if allowed != {"S-1-5-18", "S-1-5-32-544"}:
        raise ValueError("Enrollment directory permissions are not private")


def _private_directory(path):
    _no_links(path)
    if os.name == "nt":
        _windows_private(path, create=not path.exists())
    else:
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Enrollment directory permissions are not private")
    _no_links(path)


def _bytes(value):
    return value.encode("ascii") if isinstance(value, str) else value


def _read_private(path):
    _no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
        raise ValueError("Invalid enrollment credential file")
    if os.name == "nt":
        _windows_private(path, directory=False)
    elif info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Enrollment credential permissions are not private")
    return path.read_bytes()


def _write_once(path, value):
    value = _bytes(value)
    if not isinstance(value, bytes) or len(value) > MAX_FILE:
        raise ValueError("Invalid enrollment credential size")
    _no_links(path)
    if path.exists():
        if _read_private(path) != value:
            raise ValueError("Existing enrollment credential differs")
        return
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def _validate_local_identity(key, csr, computer):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    private = serialization.load_pem_private_key(key, password=None)
    request = x509.load_pem_x509_csr(csr)
    public_format = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                         computer if len(computer) <= 64 else "RDP Guard Windows client")])
    san = request.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    if (not request.is_signature_valid or len(request.extensions) != 1 or san.critical
            or list(san.value) != [x509.DNSName(computer)] or request.subject != subject
            or private.public_key().public_bytes(*public_format) != request.public_key().public_bytes(*public_format)):
        raise ValueError("Stored enrollment identity does not match")


def _prepare(data_dir, document, computer, trusted_relay):
    root = Path(data_dir).absolute() / "proxy"
    _private_directory(root)
    directory = root / ("enrollment-" + str(uuid.UUID(document["pairing_id"])))
    _private_directory(directory)
    digest = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    manifest = json.dumps({"document_sha256": digest, "computer": computer, "trusted_relay": trusted_relay},
                          sort_keys=True).encode()
    key_path, csr_path, manifest_path = directory / "client.key", directory / "client.csr", directory / "identity.json"
    if manifest_path.exists():
        if _read_private(manifest_path) != manifest:
            raise ValueError("Pairing file does not match the stored identity")
        key, csr = _read_private(key_path), _read_private(csr_path)
        _validate_local_identity(key, csr, computer)
    else:
        if key_path.exists() or csr_path.exists():
            raise ValueError("Incomplete local enrollment identity requires administrator review")
        key, csr = map(_bytes, create_client_identity(computer))
        _validate_local_identity(key, csr, computer)
        _write_once(key_path, key)
        _write_once(csr_path, csr)
        _write_once(manifest_path, manifest)
    return directory, key, csr


def _binding(document, computer, directory):
    return dict(enabled=True, mode="monitor", computer=computer, agent_url=document["agent_url"],
                stream_id=document["stream_id"], backend_id=document["backend_id"],
                relay_ips=document["relay_ips"], ca_file=str(directory / "ca.pem"),
                cert_file=str(directory / "client.pem"), key_file=str(directory / "client.key"))


class EnrollmentManager:
    def __init__(self, guard, *, transport_factory=PairingTransport, computer_reader=native_computer):
        self.guard, self.transport_factory, self.computer_reader = guard, transport_factory, computer_reader
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._cancel = threading.Event()
        self._generation = 0
        self._thread = None
        self._state = {"state": "idle"}

    def status(self):
        with self._lock:
            return dict(self._state)

    def _validated(self, document):
        try:
            return validate_pairing(document, now=self.guard.clock())
        except Exception:
            # Dispatcher audits rejected commands. Never include user-supplied JSON, tokens or PEM.
            raise ValueError("Pairing file is invalid, unsupported or expired") from None

    def preview(self, document):
        document = self._validated(document)
        computer = self.computer_reader()
        return {key: document[key] for key in ("agent_url", "stream_id", "backend_id", "listener_ip",
                "listener_port", "backend_ip", "backend_port", "relay_ips", "whitelist", "expires_at")} | {
                    "computer": computer, "mode": "monitor"}

    def start(self, document, trusted_relay, actor):
        document = self._validated(document)
        try:
            relay = address(trusted_relay)
            if relay not in document["relay_ips"]:
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError("Explicitly select a relay IP declared in the pairing file") from None
        computer = self.computer_reader()
        # Caller holds Guard.lock. This method never waits for the worker.
        previous = self.guard.store.get("proxy_binding", {"enabled": False})
        recovering = previous.get("enabled") is True
        if recovering:
            directory = Path(self.guard.data_dir).absolute() / "proxy" / ("enrollment-" + document["pairing_id"])
            if dict(previous, mode="monitor") != _binding(document, computer, directory):
                raise ValueError("Disable the existing proxy binding before pairing a new agent")
        if any(contains(row["network"], relay) for row in self.guard.store.rows(
                "SELECT network FROM blocks WHERE ended IS NULL")):
            raise ValueError("Trusted relay overlaps an existing block; review that block first")
        with self._lock:
            if self._closed.is_set():
                raise ValueError("Enrollment service is stopping")
            if self._thread is not None and self._thread.is_alive():
                raise ValueError("Proxy pairing is already in progress")
            self._generation += 1
            generation = self._generation
            cancel = self._cancel = threading.Event()
            self._state = {"state": "preparing", "computer": computer, "agent_url": document["agent_url"],
                           "stream_id": document["stream_id"], "backend_id": document["backend_id"],
                           "trusted_relay": relay, "expires_at": document["expires_at"], "error": ""}
            self._thread = threading.Thread(target=self._run,
                args=(document, relay, computer, actor, previous, generation, cancel, recovering),
                name="proxy-pairing", daemon=True)
            self._thread.start()
            return dict(self._state)

    def _state_change(self, generation, **values):
        with self._lock:
            if generation == self._generation:
                self._state.update(values)

    def cancel(self):
        with self._lock:
            self._generation += 1
            self._cancel.set()
            if self._state.get("state") in ("preparing", "connecting", "retrying", "verifying", "completing"):
                self._state.update(state="cancelled", error="Pairing cancelled by a configuration change")

    def close(self):
        self._closed.set()
        self.cancel()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(10)

    def _run(self, document, relay, computer, actor, previous, generation, cancel, recovering=False):
        def stopped():
            return self._closed.is_set() or cancel.is_set()

        phase = "Local credential preparation failed"
        try:
            directory, key, csr = _prepare(self.guard.data_dir, document, computer, relay)
            deadline = time.monotonic() + max(0, document["expires_at"] - self.guard.clock())
            transport = self.transport_factory(document)
            if recovering:
                phase = "Stored pairing credentials could not be verified"
                certificate = _read_private(directory / "client.pem").decode("ascii")
                if _read_private(directory / "ca.pem") != document["ca_pem"].encode("ascii"):
                    raise ValueError
                fingerprint = validate_client_certificate(certificate, key.decode("ascii"), document["ca_pem"], computer)
            else:
                while not stopped():
                    if self.guard.clock() >= document["expires_at"] or time.monotonic() >= deadline:
                        raise PairingError("expired")
                    phase = "Agent identity verification or enrollment failed"
                    self._state_change(generation, state="connecting")
                    try:
                        receipt = transport.enroll(computer, csr.decode("ascii"))
                        break
                    except PairingRetryableError:
                        self._state_change(generation, state="retrying")
                        if cancel.wait(2):
                            return
                else:
                    return
                if stopped():
                    return
                self._state_change(generation, state="verifying")
                phase = "Agent returned an invalid client certificate or binding"
                if (not isinstance(receipt, dict) or receipt.get("ok") is not True
                        or receipt.get("pairing_id") != document["pairing_id"]
                        or receipt.get("computer", "").rstrip(".").upper() != computer.rstrip(".").upper()
                        or any(receipt.get(name) != document[name] for name in ("stream_id", "backend_id"))):
                    raise ValueError
                certificate = receipt.get("client_pem")
                fingerprint = validate_client_certificate(certificate, key.decode("ascii"), document["ca_pem"], computer)
                if receipt.get("client_sha256") != fingerprint:
                    raise ValueError
                _write_once(directory / "ca.pem", document["ca_pem"])
                _write_once(directory / "client.pem", certificate)
            binding = validate_binding(self.guard.data_dir, _binding(document, computer, directory))
            phase = "Configuration changed or relay conflicts with an existing block; pairing was not applied"
            # Never acquire Guard.lock while holding the manager state lock. Shutdown can
            # cancel this job even when another Guard operation is still finishing.
            with self.guard.lock:
                if stopped() or getattr(self.guard, "stopping", False):
                    return
                with self._lock:
                    current = generation == self._generation
                if not current or self.guard.store.get("proxy_binding", {"enabled": False}) != previous:
                    raise ValueError
                if self.guard.clock() >= document["expires_at"] or time.monotonic() >= deadline:
                    raise ValueError
                if not recovering:
                    self.guard._commit_proxy_binding(binding, actor, trusted_relay=relay)
            # The acknowledgement is sent only after keys, certificate and binding
            # are durable. Losing its response must never roll that binding back.
            self._state_change(generation, state="completing", mode=previous.get("mode", "monitor") if recovering else "monitor",
                               handoff_pending=True, error="")
            acknowledged = False
            ack_deadline = min(deadline, time.monotonic() + 20)
            while not stopped() and time.monotonic() < ack_deadline and self.guard.clock() < document["expires_at"]:
                try:
                    acknowledgement = transport.complete(computer, fingerprint)
                    if (not isinstance(acknowledgement, dict) or acknowledgement.get("ok") is not True
                            or acknowledgement.get("completed") is not True
                            or acknowledgement.get("pairing_id") != document["pairing_id"]):
                        break
                    acknowledged = True
                    break
                except PairingRetryableError:
                    if cancel.wait(2):
                        return
                except Exception:
                    break
            self._state_change(generation, state="paired", handoff_pending=not acknowledged,
                               error="" if acknowledged else "Pairing saved; final Linux handoff is not confirmed. Check fresh agent status or retry the same file before expiry.")
        except Exception:
            self._state_change(generation, state="failed", error=phase)
