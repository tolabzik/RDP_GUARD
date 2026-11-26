"""Optional mTLS evidence worker. No network operation holds Guard.lock."""
from __future__ import annotations

import hashlib
import http.client
import json
import math
from pathlib import Path
import re
import socket
import ssl
import threading
import time
import uuid
from urllib.parse import urlsplit

from .models import address
from .proxy_evidence import instant, ip, read_windows, windows_log_coverage
from .windows.proxy_export import MAX_BYTES, NativeProxyExporter, utc


RETRY_SECONDS = 120
RESPONSE_LIMIT = 1024 * 1024
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
BINDING_FIELDS = {"enabled", "agent_url", "stream_id", "backend_id", "computer", "ca_file", "cert_file",
                  "key_file", "relay_ips", "mode"}


def _credential_path(data_dir, value):
    if not isinstance(value, str):
        raise ValueError("Proxy credential file must be an absolute path")
    path, root = Path(value), Path(data_dir).absolute() / "proxy"
    if not path.is_absolute():
        raise ValueError("Proxy credential file must be an absolute path")
    # Reject junctions as well as symlinks before resolving the location.
    for item in (path, *path.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("Proxy credential paths cannot contain links")
    for item in (root, *root.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("Proxy credential directory cannot contain links")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        if not resolved.is_file() or resolved.stat().st_size > 1024 * 1024:
            raise ValueError
    except (OSError, ValueError):
        raise ValueError("Proxy credential files must exist inside the protected proxy directory") from None
    return str(resolved)


def validate_binding(data_dir, args):
    if not isinstance(args, dict) or type(args.get("enabled", False)) is not bool:
        raise ValueError("Proxy binding must contain a boolean enabled field")
    if set(args) - BINDING_FIELDS:
        raise ValueError("Unknown proxy binding fields")
    if not args.get("enabled", False):
        return {"enabled": False}
    result = {"enabled": True}
    for field in ("stream_id", "backend_id"):
        value = args.get(field)
        if not isinstance(value, str) or not SLUG.fullmatch(value):
            raise ValueError(f"Invalid proxy {field}")
        result[field] = value
    computer = args.get("computer")
    if not isinstance(computer, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", computer):
        raise ValueError("Proxy computer must be the native Windows host name")
    result["computer"] = computer
    value = args.get("agent_url")
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 for c in value):
        raise ValueError("Invalid proxy agent URL")
    try:
        url = urlsplit(value)
        port = url.port if url.port is not None else 443
        if (url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None
                or url.path not in ("", "/") or url.query or url.fragment or not 1 <= port <= 65535):
            raise ValueError
    except ValueError:
        raise ValueError("Proxy agent URL must be an HTTPS origin without credentials or a path") from None
    result["agent_url"] = value.rstrip("/")
    for field in ("ca_file", "cert_file", "key_file"):
        result[field] = _credential_path(data_dir, args.get(field))
    relays = args.get("relay_ips")
    if not isinstance(relays, list) or not 1 <= len(relays) <= 32:
        raise ValueError("Proxy binding requires 1 to 32 relay IP addresses")
    try:
        result["relay_ips"] = sorted({address(value) for value in relays})
    except ValueError:
        raise ValueError("Invalid proxy relay IP address") from None
    if args.get("mode") not in ("monitor", "enforce"):
        raise ValueError("Proxy mode must be monitor or enforce")
    result["mode"] = args["mode"]
    return result


def binding_id(binding):
    return hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()


def _clean_text(value, limit=200):
    return "".join(c for c in value if c.isprintable())[:limit] if isinstance(value, str) else ""


def sanitize_status(receipt):
    if not isinstance(receipt, dict) or receipt.get("ok") is not True or not isinstance(receipt.get("status"), dict):
        raise ValueError("Invalid proxy agent receipt")
    status, clean = receipt["status"], {}
    for name in ("healthy", "enforcement_allowed", "capture_healthy"):
        if type(status.get(name)) is bool:
            clean[name] = status[name]
    for name in ("matched", "unresolved", "proposed", "active_bans"):
        if type(status.get(name)) is int and 0 <= status[name] <= 2**63 - 1:
            clean[name] = status[name]
    for name in ("mode", "capture_epoch", "stream_id", "backend_id", "computer"):
        if isinstance(status.get(name), str):
            clean[name] = _clean_text(status[name])
    for name in ("checkpoint_utc", "last_evidence_utc"):
        value = status.get(name)
        if value is None:
            clean[name] = None
        else:
            instant(value)
            clean[name] = value[:64]
    if status.get("error"):
        clean["error"] = "Proxy agent reported an error; inspect its protected journal"
    else:
        clean["error"] = ""
    results = receipt.get("results", [])
    if not isinstance(results, list) or len(results) > 100:
        raise ValueError("Invalid proxy agent result count")
    clean["results"] = []
    for item in results:
        if not isinstance(item, dict):
            raise ValueError("Invalid proxy agent result")
        result = {}
        if "client_ip" in item:
            result["client_ip"] = ip(item["client_ip"])
        for name in ("attempts", "failure_record_id"):
            if type(item.get(name)) is int and 0 <= item[name] <= 2**63 - 1:
                result[name] = item[name]
        for name in ("status", "reason"):
            if isinstance(item.get(name), str):
                result[name] = _clean_text(item[name])
        if item.get("expires") is None or (type(item.get("expires")) in (int, float)
                                          and math.isfinite(item["expires"]) and item["expires"] >= 0):
            result["expires"] = item.get("expires")
        clean["results"].append(result)
    return clean


class ProxyTransport:
    def __init__(self, binding, connection_factory=http.client.HTTPSConnection, context_factory=ssl.create_default_context):
        self.binding, self.connection_factory, self.context_factory = binding, connection_factory, context_factory

    def post(self, endpoint, envelope):
        if endpoint not in ("/v1/evidence", "/v1/status", "/v1/unblock", "/v1/results"):
            raise ValueError("Unsupported proxy API endpoint")
        body = json.dumps(envelope, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(body) > MAX_BYTES:
            raise ValueError("Proxy request exceeds size limit")
        cfg = self.binding
        context = self.context_factory(cafile=cfg["ca_file"])
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=cfg["cert_file"], keyfile=cfg["key_file"])
        url = urlsplit(cfg["agent_url"])
        connection = self.connection_factory(url.hostname, url.port or 443, timeout=5, context=context)
        expired = threading.Event()

        def expire():
            expired.set()
            sock = getattr(connection, "sock", None)
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        timer = threading.Timer(5, expire)
        timer.daemon = True
        timer.start()
        try:
            connection.request("POST", endpoint, body=body, headers={"Content-Type": "application/json", "Accept": "application/json"})
            if expired.is_set():
                raise TimeoutError("Proxy request timed out")
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError("Proxy agent rejected the request")
            data = response.read(RESPONSE_LIMIT + 1)
            if expired.is_set():
                raise TimeoutError("Proxy response timed out")
            if len(data) > RESPONSE_LIMIT:
                raise ValueError("Proxy response exceeds size limit")
            receipt = json.loads(data.decode("utf-8"))
            sanitize_status(receipt)
            return receipt
        finally:
            timer.cancel()
            connection.close()


class ProxyWorker(threading.Thread):
    def __init__(self, guard, stop, *, exporter=None, transport_factory=ProxyTransport, clock=time.time):
        super().__init__(name="proxy-evidence", daemon=True)
        self.guard, self.stop, self.clock = guard, stop, clock
        self.exporter = exporter or NativeProxyExporter(clock=clock)
        self.transport_factory = transport_factory
        self.phase = "configuration"

    def _mode(self, cfg, now):
        if cfg["mode"] != "enforce" or self.guard.mode != "ACTIVE" or self.guard.emergency_path.exists():
            return "monitor"
        try:
            lease = json.loads(self.guard.lease_path.read_text(encoding="utf-8"))
            if (lease.get("confirmed") is True and lease.get("deadline") is None
                    and now - 45 <= lease["heartbeat"] <= now + 10):
                return "enforce"
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return "monitor"

    def _status(self, value):
        if not self.stop.is_set():
            self.guard.store.set("proxy_status", dict(value, updated_at_utc=utc(self.clock())))

    @staticmethod
    def _receipt(cfg, receipt):
        clean = sanitize_status(receipt)
        if (clean.get("stream_id") != cfg["stream_id"] or clean.get("backend_id") != cfg["backend_id"]
                or clean.get("computer", "").rstrip(".").casefold() != cfg["computer"].rstrip(".").casefold()):
            raise ValueError("Proxy receipt does not belong to this binding")
        return clean

    @staticmethod
    def _document(cfg, document, now):
        events, issues = read_windows(document)
        start, end = instant(document["requested_start_utc"]), instant(document["requested_end_utc"])
        if (issues or windows_log_coverage(document, events)["status"] != "retained"
                or document.get("computer", "").rstrip(".").casefold() != cfg["computer"].rstrip(".").casefold()
                or document.get("event_count") != len(document.get("events", []))
                or not 0 <= now - end <= RETRY_SECONDS or abs(end - start - 30) > 0.000001
                or abs(start - instant(document["query_start_utc"]) - 5) > 0.000001
                or document.get("max_events") != 5000 or document.get("lookback_seconds") != 5):
            raise ValueError("Proxy evidence is incomplete or native host/retention/window checks failed")

    def _unblocks(self, cfg, key, now):
        # Guard dispatch uses the same lock when appending. Only queue bookkeeping
        # is locked; the TLS request runs after the lock has been released.
        with self.guard.lock:
            queue = self.guard.store.get("proxy_unblock_queue", [])
            if not isinstance(queue, list) or len(queue) > 100:
                raise ValueError("Invalid proxy unblock queue")
            valid = []
            for item in queue:
                try:
                    if (not uuid.UUID(item["id"]).int or item["binding_id"] != key
                            or type(item["created"]) not in (int, float)
                            or not 0 <= now - item["created"] <= RETRY_SECONDS):
                        continue
                    ip(item["client_ip"])
                    valid.append(item)
                except (ValueError, TypeError, KeyError, AttributeError):
                    continue
            discarded = len(queue) - len(valid)
            if discarded:
                self.guard.store.set("proxy_unblock_queue", valid)
                self.guard.store.audit("proxy-worker", "unblock-requests-discarded", {"count": discarded}, now)
        if not valid or self.stop.is_set():
            return discarded
        current = validate_binding(self.guard.data_dir, self.guard.store.get("proxy_binding", {}))
        if binding_id(current) != key:
            return discarded
        self.phase = "unblock delivery"
        item = valid[0]
        clean = self._receipt(current, self.transport_factory(current).post("/v1/unblock", dict(
            stream_id=current["stream_id"], backend_id=current["backend_id"], client_ip=item["client_ip"])))
        if self.stop.is_set():
            return discarded
        with self.guard.lock:
            remaining = self.guard.store.get("proxy_unblock_queue", [])
            self.guard.store.set("proxy_unblock_queue", [row for row in remaining if row.get("id") != item["id"]])
        self._status(dict(clean, enabled=True, transport_healthy=True, last_unblock_utc=utc(self.clock()),
                          discarded_unblock_requests=discarded, binding_id=key))
        return discarded

    def step(self):
        if self.stop.is_set():
            return
        store, now = self.guard.store, self.clock()
        self.phase = "configuration"
        cfg = validate_binding(self.guard.data_dir, store.get("proxy_binding", {}))
        if not cfg["enabled"]:
            if store.get("proxy_outbox") is not None:
                store.set("proxy_outbox", None)
            return
        key = binding_id(cfg)
        discarded_unblocks = self._unblocks(cfg, key, now)
        if self.stop.is_set():
            return
        pending = store.get("proxy_outbox")
        discarded = False
        if pending is not None:
            try:
                valid = (pending["binding_id"] == key and 0 <= now - pending["created_at"] <= RETRY_SECONDS
                         and 0 <= now - instant(pending["document"]["requested_end_utc"]) <= RETRY_SECONDS
                         and len(json.dumps(pending).encode("utf-8")) <= MAX_BYTES)
            except (KeyError, TypeError, ValueError):
                valid = False
            if not valid:
                pending, discarded = None, True
                store.set("proxy_outbox", None)
        if pending is None:
            self.phase = "native evidence export"
            document = self.exporter.export(utc(now - 32), utc(now - 2), lookback_seconds=5, max_events=5000)
            self._document(cfg, document, now)
            pending = dict(binding_id=key, created_at=now, mode=self._mode(cfg, now), document=document)
            if len(json.dumps(pending).encode("utf-8")) > MAX_BYTES - 4096:
                raise ValueError("Proxy outbox exceeds size limit")
            if self.stop.is_set():
                return
            store.set("proxy_outbox", pending)
        self._document(cfg, pending["document"], self.clock())
        # Configuration can be changed while native reads or a previous send are running.
        current = validate_binding(self.guard.data_dir, store.get("proxy_binding", {}))
        if binding_id(current) != key or self.stop.is_set():
            return
        mode = self._mode(current, self.clock())
        if pending.get("mode") != "enforce":
            mode = "monitor"  # A retry cannot promote a previously monitoring snapshot.
        envelope = dict(stream_id=cfg["stream_id"], backend_id=cfg["backend_id"], mode=mode,
                        document=pending["document"])
        self.phase = "evidence delivery"
        receipt = self.transport_factory(current).post("/v1/evidence", envelope)
        clean = self._receipt(current, receipt)
        if self.stop.is_set():
            return
        if binding_id(validate_binding(self.guard.data_dir, store.get("proxy_binding", {}))) != key:
            return
        store.set("proxy_outbox", None)
        self._status(dict(clean, enabled=True, transport_healthy=True, outbox_pending=False,
                          outgoing_mode=mode, discarded_stale_snapshot=discarded,
                          discarded_unblock_requests=discarded_unblocks, last_sent_utc=utc(self.clock()),
                          binding_id=key))

    def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            try:
                self.step()
            except Exception as exc:
                if self.stop.is_set():
                    break
                self._status(dict(enabled=True, healthy=False, transport_healthy=False,
                                  error=f"Proxy {self.phase} failed ({type(exc).__name__})",
                                  outbox_pending=self.guard.store.get("proxy_outbox") is not None))
            self.stop.wait(max(0, 5 - (time.monotonic() - started)))
