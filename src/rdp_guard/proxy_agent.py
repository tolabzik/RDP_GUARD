"""Experimental proxy agent. Mutual TLS authenticates one Windows/stream binding.

The HTTP API accepts native evidence, never a request to ban an arbitrary IP.
Enforcement additionally requires local validation/opt-in; the default is observation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import signal
import socket
import sqlite3
import ssl
import sys
import threading
import time
import uuid

from defusedxml import ElementTree as ET

from .models import address, contains, network
from .proxy_evidence import (correlate_evidence, guid, instant, integer,
                             named_data, read_windows, windows_log_coverage)

LOG = logging.getLogger(__name__)
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
MAX_BODY = 32 * 1024 * 1024
MAX_PENDING = 32
MAX_SUPPRESSIONS = 10000
REQUEST_DEADLINE_SECONDS = 10
SCHEMA = """
CREATE TABLE IF NOT EXISTS identity(id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT);
CREATE TABLE IF NOT EXISTS pending(id TEXT PRIMARY KEY, received REAL, document TEXT, mode TEXT, generation TEXT);
CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY, timestamp REAL, client_ip TEXT,
 connection_id TEXT UNIQUE, attempts INTEGER, status TEXT, reason TEXT, expires REAL, generation TEXT, proof TEXT);
CREATE INDEX IF NOT EXISTS decisions_time ON decisions(timestamp);
CREATE INDEX IF NOT EXISTS decisions_client_time ON decisions(client_ip,timestamp);
CREATE TABLE IF NOT EXISTS bans(client_ip TEXT PRIMARY KEY, created REAL, expires REAL);
CREATE TABLE IF NOT EXISTS suppression(client_ip TEXT PRIMARY KEY, until REAL);
"""


def utc(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat()


def slug(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", value):
        raise ValueError("Expected a short stream/backend identifier")
    return value


def absolute_path(value):
    # The Linux service configuration can be validated on a Windows build host.
    return isinstance(value, str) and (PurePosixPath(value).is_absolute() or Path(value).is_absolute())


def load_config(value):
    """Reject ambiguous configuration before opening sockets or touching firewall."""
    if not isinstance(value, dict):
        raise ValueError("Agent configuration must be an object")
    required = {"stream_id", "backend_id", "computer", "client_sha256", "api_host", "api_port",
                "ca_file", "cert_file", "key_file", "nginx_log", "backend_ip", "backend_port",
                "listener_ip", "listener_port", "relay_ips", "nginx_utc_offset_minutes", "whitelist"}
    optional = {"schema", "nginx_pid_namespace", "threshold", "window_seconds", "ban_seconds",
                "max_blocks", "max_blocks_per_minute", "enforcement_validated", "protocols",
                "state_file", "epoch_seconds", "max_records", "max_log_bytes"}
    if required - value.keys() or value.keys() - required - optional:
        raise ValueError("Missing or unknown agent configuration fields")
    cfg = dict(value)
    if cfg.get("schema", "rdpguard.proxy-agent.v1") != "rdpguard.proxy-agent.v1":
        raise ValueError("Unsupported agent configuration schema")
    for key in ("stream_id", "backend_id"):
        cfg[key] = slug(cfg[key])
    if not isinstance(cfg["computer"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", cfg["computer"]):
        raise ValueError("Expected the exact native Windows computer name")
    if not isinstance(cfg["client_sha256"], str) or not re.fullmatch(r"[a-fA-F0-9]{64}", cfg["client_sha256"]):
        raise ValueError("Expected the SHA256 fingerprint of the Windows client certificate")
    cfg["client_sha256"] = cfg["client_sha256"].lower()
    for key in ("api_host", "backend_ip", "listener_ip"):
        parsed = ipaddress.ip_address(cfg[key])
        cfg[key] = str(parsed.ipv4_mapped or parsed) if parsed.version == 6 else str(parsed)
    for key in ("backend_ip", "listener_ip"):
        address(cfg[key])
        if ipaddress.ip_address(cfg[key]).is_link_local:
            raise ValueError("Backend/listener must use routable unicast addresses")
    for key in ("api_port", "backend_port", "listener_port"):
        cfg[key] = integer(cfg[key], 1, 65535)
    for key in ("ca_file", "cert_file", "key_file", "nginx_log"):
        if not absolute_path(cfg[key]):
            raise ValueError("Agent paths must be absolute")
    if not isinstance(cfg["relay_ips"], list) or not 1 <= len(cfg["relay_ips"]) <= 16:
        raise ValueError("Specify the native Windows peer IPs for this proxy")
    cfg["relay_ips"] = sorted({address(item) for item in cfg["relay_ips"]})
    if not isinstance(cfg["whitelist"], list) or not 1 <= len(cfg["whitelist"]) <= 1000:
        raise ValueError("Configure at least one real administrator address/network on the agent")
    cfg["whitelist"] = sorted({network(item) for item in cfg["whitelist"]})
    integer(cfg["nginx_utc_offset_minutes"], -840, 840)
    for key, default, minimum, maximum in (
            ("threshold", 10, 2, 1000), ("window_seconds", 300, 30, 3600),
            ("ban_seconds", 3600, 60, 86400), ("max_blocks", 4000, 1, 10000),
            ("max_blocks_per_minute", 20, 1, 1000)):
        cfg[key] = integer(cfg.get(key, default), minimum, maximum)
    cfg.setdefault("enforcement_validated", False)
    if type(cfg["enforcement_validated"]) is not bool:
        raise ValueError("enforcement_validated must be boolean")
    cfg.setdefault("protocols", ["tcp"])
    if cfg["protocols"] not in (["tcp"], ["tcp", "udp"]):
        raise ValueError("Publish TCP explicitly; add UDP only if that listener is actually published")
    cfg.setdefault("state_file", "/var/lib/rdpguard-proxy/state.sqlite3")
    if not absolute_path(cfg["state_file"]):
        raise ValueError("State path must be absolute")
    from .proxy_capture import capture_config
    return capture_config(cfg)


class LeasedFirewall:
    """Translate logical decisions into short native kernel leases."""
    def __init__(self, config, clock=time.time):
        from .proxy_firewall import ProxyFirewallConfig, ScopedNftFirewall
        self.clock = clock
        protection = set(config["whitelist"]) | {
            network(item) for item in config["relay_ips"] + [config["backend_ip"], config["listener_ip"]]}
        self.backend = ScopedNftFirewall(ProxyFirewallConfig(
            stream_id=config["stream_id"], listener_ip=config["listener_ip"], listener_port=config["listener_port"],
            protocols=tuple(config["protocols"]), whitelist=tuple(sorted(protection)),
            enforcement_approved=config["enforcement_validated"], max_entries=config["max_blocks"],
            max_new_bans_per_minute=config["max_blocks_per_minute"], max_ttl_seconds=30))

    def sync(self, bans):
        from .proxy_firewall import ProxyBan
        now = self.clock()
        result = self.backend.sync([ProxyBan(ip, now + ttl) for ip, ttl in bans.items() if ttl > 0],
                                   mode="enforce", now=now)
        if not result.applied or result.plan is None:
            raise RuntimeError("Native firewall did not verify application")
        return {ban.client_ip: ban.expires_at for ban in result.plan.bans}


def verify_document(document, computer, now):
    """Verify signed-in transport data against native XML and retained log bounds."""
    if not isinstance(document, dict) or not isinstance(document.get("events"), list):
        raise ValueError("Expected native Windows evidence")
    if len(document["events"]) > 5000 or document.get("event_count") != len(document["events"]):
        raise ValueError("Invalid evidence count")
    start, end, query = (instant(document[key]) for key in
                         ("requested_start_utc", "requested_end_utc", "query_start_utc"))
    if not now - 120 <= end <= now + 2 or not 0 < end - start <= 60 or not 0 <= start - query <= 30:
        raise ValueError("Evidence window is stale, in the future, or too large")
    if str(document.get("computer", "")).rstrip(".").casefold() != computer.rstrip(".").casefold():
        raise ValueError("Evidence belongs to a different Windows backend")
    events, issues = read_windows(document)
    if issues or windows_log_coverage(document, events)["status"] != "retained":
        raise ValueError("Incomplete or inconsistent native evidence")
    for row in document["events"]:
        xml = row.get("xml") or row.get("raw_xml")
        if not isinstance(xml, str) or len(xml) > 131072:
            raise ValueError("Native XML is required")
        root = ET.fromstring(xml)
        system = root.find("e:System", NS)
        if system is None:
            raise ValueError("Missing native System element")
        provider = system.find("e:Provider", NS)
        correlation = system.find("e:Correlation", NS)
        stamp = system.find("e:TimeCreated", NS)
        if provider is None or correlation is None or stamp is None:
            raise ValueError("Incomplete native identity")
        native = {
            "channel": system.findtext("e:Channel", namespaces=NS),
            "computer": system.findtext("e:Computer", namespaces=NS),
            "event_id": int(system.findtext("e:EventID", namespaces=NS)),
            "record_id": int(system.findtext("e:EventRecordID", namespaces=NS)),
            "version": int(system.findtext("e:Version", namespaces=NS)),
            "provider_name": provider.get("Name"),
        }
        fields = root.findall("e:EventData/e:Data", NS)
        data = {field.get("Name"): field.text or "" for field in fields}
        if (any(row.get(key) != item for key, item in native.items())
                or native["computer"].rstrip(".").casefold() != computer.rstrip(".").casefold()
                or guid(provider.get("Guid")) != guid(row["provider_guid"])
                or guid(correlation.get("ActivityID")) != guid(row["activity_id"])
                or instant(stamp.get("SystemTime")) != instant(row["timestamp_utc"])
                or len(data) != len(fields) or data != named_data(row["data"])):
            raise ValueError("Native XML and exported event fields disagree")
    return events


class Agent:
    """Durable decisions scoped to exactly one listener and one certificate."""

    def __init__(self, config, capture, firewall=None, clock=time.time, database=None, monotonic=time.monotonic):
        self.config, self.capture, self.firewall, self.clock = config, capture, firewall, clock
        self.monotonic = monotonic
        self.lock = threading.RLock()
        self.db = sqlite3.connect(database or config["state_file"], check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;" + SCHEMA)
        if self.db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Proxy state integrity check failed")
        binding = json.dumps({key: config[key] for key in ("stream_id", "backend_id", "computer", "client_sha256",
                             "backend_ip", "backend_port", "listener_ip", "listener_port", "relay_ips", "protocols")},
                             sort_keys=True)
        previous = self.db.execute("SELECT binding FROM identity WHERE id=1").fetchone()
        if previous and previous[0] != binding:
            self.db.close()
            raise ValueError("State database belongs to a different proxy binding; use a fresh state file")
        self.db.execute("INSERT OR IGNORE INTO identity VALUES (1,?)", (binding,))
        # Service restart never restores authority from a previous Windows heartbeat.
        self.mode, self.last_evidence, self.error = "monitor", 0, ""
        self.activation_generation, self.activation_at = "observation", float("inf")
        self.applied_until = {}
        self.applied_monotonic = {}
        self.last_firewall_monotonic = float("-inf")
        self.capture_epoch, self.capture_healthy, self.checkpoint = "", False, None
        self.unresolved, self.last_firewall = 0, 0

    def authorize(self, fingerprint, envelope):
        if fingerprint != self.config["client_sha256"]:
            raise PermissionError("Client certificate is not enrolled")
        if not isinstance(envelope, dict) or any(envelope.get(key) != self.config[key]
                                              for key in ("stream_id", "backend_id")):
            raise PermissionError("Certificate is not bound to this stream/backend")

    def handle(self, path, envelope, fingerprint):
        with self.lock:
            self.authorize(fingerprint, envelope)
            if path == "/v1/status":
                if set(envelope) != {"stream_id", "backend_id"}:
                    raise ValueError("Unknown status fields")
            elif path == "/v1/evidence":
                if set(envelope) != {"stream_id", "backend_id", "mode", "document"}:
                    raise ValueError("Unknown evidence fields")
                if envelope["mode"] not in ("monitor", "enforce"):
                    raise ValueError("Unknown proxy mode")
                document, now = envelope["document"], self.clock()
                verify_document(document, self.config["computer"], now)
                encoded = json.dumps(document, sort_keys=True, separators=(",", ":"))
                key = hashlib.sha256(encoded.encode()).hexdigest()
                exists = self.db.execute("SELECT 1 FROM pending WHERE id=?", (key,)).fetchone()
                pending = self.db.execute("SELECT COUNT(*),COALESCE(SUM(LENGTH(document)),0) FROM pending").fetchone()
                if not exists and (pending[0] >= MAX_PENDING or pending[1] + len(encoded.encode()) > MAX_BODY):
                    self.mode = "monitor"
                    raise ValueError("Evidence queue is full; new enforcement suspended")
                cutoff = instant(document["requested_end_utc"])
                # A replay may always reduce authority, but only a strictly
                # advancing native cutoff can establish a new active generation.
                if envelope["mode"] == "monitor":
                    self.mode = "monitor"
                    self.db.execute("DELETE FROM bans")
                elif cutoff > self.last_evidence and self.mode != "enforce":
                    self.mode = "enforce"
                    self.activation_generation = str(uuid.uuid4())
                    self.activation_at = now
                generation = self.activation_generation if self.mode == "enforce" else "observation"
                pending_mode = "enforce" if self.mode == "enforce" and cutoff > self.last_evidence else "monitor"
                self.db.execute("INSERT OR IGNORE INTO pending VALUES (?,?,?,?,?)",
                                (key, now, encoded, pending_mode, generation))
                # The event cutoff, not HTTP receipt time, supplies the liveness proof.
                # Replaying an identical export cannot extend this deadline.
                self.last_evidence = max(self.last_evidence, cutoff)
            elif path == "/v1/unblock":
                if set(envelope) != {"stream_id", "backend_id", "client_ip"}:
                    raise ValueError("Unknown unblock fields")
                client = address(envelope["client_ip"])
                self.db.execute("DELETE FROM suppression WHERE until<=?", (self.clock(),))
                if (not self.db.execute("SELECT 1 FROM suppression WHERE client_ip=?", (client,)).fetchone()
                        and self.db.execute("SELECT COUNT(*) FROM suppression").fetchone()[0] >= MAX_SUPPRESSIONS):
                    raise ValueError("Manual unblock capacity reached")
                self.db.execute("DELETE FROM bans WHERE client_ip=?", (client,))
                self.db.execute("INSERT OR REPLACE INTO suppression VALUES (?,?)",
                                (client, self.clock() + self.config["window_seconds"]))
                status = "removal_pending" if self.applied_until.get(client, 0) > self.clock() else "removed"
                self.db.execute("UPDATE decisions SET status=?,expires=NULL WHERE client_ip=?", (status, client))
                self.last_firewall = 0
            else:
                raise LookupError("Unknown agent endpoint")
            return {"ok": True, "status": self.status(), "results": self.results()}

    def _protected(self, client):
        infrastructure = set(self.config["relay_ips"]) | {
            self.config["listener_ip"], self.config["backend_ip"], self.config["api_host"]}
        return client in infrastructure or any(contains(net, client) for net in self.config["whitelist"])

    def _record(self, result, now, eligible, generation):
        if result["status"] != "demonstrated_candidate" or result["proxy_ip"] not in self.config["relay_ips"]:
            return False
        client = address(result["client_ip"])
        timestamp = instant(result["failure_timestamp_utc"])
        key = hashlib.sha256((result["computer"] + "|" + str(result["failure_record_id"])
                              + "|" + result["failure_timestamp_utc"]).encode()).hexdigest()
        conn = result["nginx_connection"]
        connection = "|".join(str(conn[field]) for field in ("capture_id", "worker_pid", "connection_id"))
        if self.db.execute("SELECT 1 FROM decisions WHERE id=? OR connection_id=?", (key, connection)).fetchone():
            return True
        if self.db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] >= 100000:
            raise ValueError("Decision capacity reached; enforcement suspended")
        if not now - self.config["window_seconds"] <= timestamp <= now + 2:
            return True
        status = "whitelisted" if self._protected(client) else "observed"
        suppressed = self.db.execute("SELECT 1 FROM suppression WHERE client_ip=? AND until>?", (client, now)).fetchone()
        if suppressed:
            status = "removed"
        previous = self.db.execute("SELECT created FROM bans WHERE client_ip=? AND expires>?", (client, now)).fetchone()
        since = max(now - self.config["window_seconds"], previous[0] if previous else 0)
        if eligible and timestamp < self.activation_at:
            eligible = False
            generation = "observation"
        count = self.db.execute("SELECT COUNT(*) FROM decisions WHERE client_ip=? AND timestamp>=? "
                                "AND generation=? AND status NOT IN ('whitelisted','removed')",
                                (client, since, generation)).fetchone()[0] + 1
        expires = None
        if status == "observed" and count >= self.config["threshold"]:
            status = "proposed"
            capacity = self.db.execute("SELECT COUNT(*) FROM bans WHERE expires>?", (now,)).fetchone()[0]
            rate = self.db.execute("SELECT COUNT(*) FROM bans WHERE created>?", (now - 60,)).fetchone()[0]
            if eligible and not previous and capacity < self.config["max_blocks"] and rate < self.config["max_blocks_per_minute"]:
                expires = now + self.config["ban_seconds"]
                status = "pending"
        proof = json.dumps(result, sort_keys=True, separators=(",", ":"))
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (key, timestamp, client, connection, count, status, result["reason"], expires, generation, proof))
            if expires is not None:
                self.db.execute("INSERT OR REPLACE INTO bans VALUES (?,?,?)", (client, now, expires))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        return True

    def tick(self):
        with self.lock:
            now = self.clock()
            self.db.execute("DELETE FROM pending WHERE received<?", (now - 120,))
            self.db.execute("DELETE FROM decisions WHERE timestamp<?", (now - 7200,))
            self.db.execute("DELETE FROM suppression WHERE until<=?", (now,))
            self.db.execute("DELETE FROM bans WHERE expires<=?", (now,))
            snapshot = self.capture.snapshot()
            self.capture_healthy = snapshot["healthy"]
            self.capture_epoch = snapshot.get("epoch", "")
            self.checkpoint = snapshot.get("checkpoint_utc")
            self.error = snapshot.get("error", "")
            fresh = 0 <= now - self.last_evidence <= 15
            eligible = (self.mode == "enforce" and self.config["enforcement_validated"]
                        and self.capture_healthy and fresh and self.firewall is not None)
            self.unresolved = 0
            if self.capture_healthy:
                for row in self.db.execute("SELECT * FROM pending ORDER BY received").fetchall():
                    document = json.loads(row["document"])
                    report = correlate_evidence(document, snapshot["records"])
                    remaining = False
                    for result in report["results"]:
                        if result["proxy_ip"] not in self.config["relay_ips"]:
                            continue  # A different path is not a proxy mapping failure.
                        allow = eligible and row["mode"] == "enforce" and row["generation"] == self.activation_generation
                        generation = row["generation"] if allow else "observation"
                        if not self._record(result, now, allow, generation):
                            self.unresolved += 1
                            remaining = True
                    if not remaining:
                        self.db.execute("DELETE FROM pending WHERE id=?", (row["id"],))
            if self.firewall is not None and (now - self.last_firewall >= 5 or now < self.last_firewall
                                              or self.monotonic() - self.last_firewall_monotonic >= 5):
                current = self.capture.snapshot()
                if not current["healthy"] or current.get("epoch") != self.capture_epoch:
                    eligible = False
                    self.capture_healthy = False
                    self.error = "Capture changed during matching; enforcement suspended"
                # Matching a full queue can outlive the heartbeat. Authority at
                # the beginning of a tick must not renew a lease after it expires.
                apply_now = self.clock()
                fresh = 0 <= apply_now - self.last_evidence <= 15
                eligible = eligible and fresh and apply_now >= now
                # Each kernel entry is leased for <=30s. Lost evidence/agent heartbeat
                # cannot leave a persistent shared-service lockout behind.
                bans = {row["client_ip"]: min(30, int(row["expires"] - apply_now)) for row in
                        self.db.execute("SELECT * FROM bans WHERE expires>?", (apply_now,))
                        if not self._protected(row["client_ip"])} if eligible else {}
                verified = self.firewall.sync(bans)
                # Native adapter returns only read-back-verified leases. The None
                # convention is retained for the in-memory test adapter.
                self.applied_until = (verified if verified is not None else
                                      {ip: apply_now + ttl for ip, ttl in bans.items() if ttl > 0})
                finished_wall, finished_mono = self.clock(), self.monotonic()
                self.applied_monotonic = {ip: finished_mono + min(30, max(0, until - finished_wall))
                                          for ip, until in self.applied_until.items()}
                self.db.execute("UPDATE decisions SET status='suspended' WHERE status IN ('blocked','pending')")
                self.db.execute("UPDATE decisions SET status='removed' WHERE status='removal_pending'")
                if self.applied_until:
                    for ip in self.applied_until:
                        self.db.execute("UPDATE decisions SET status='blocked' WHERE client_ip=? AND expires>?",
                                        (ip, apply_now))
                self.last_firewall = apply_now
                self.last_firewall_monotonic = finished_mono
            if not fresh and self.mode == "enforce":
                self.error = "Windows evidence heartbeat is stale; new bans suspended"

    def status(self):
        now = self.clock()
        counts = dict(self.db.execute("SELECT status,COUNT(*) FROM decisions WHERE timestamp>=? GROUP BY status",
                                      (now - self.config["window_seconds"],)).fetchall())
        fresh = 0 <= now - self.last_evidence <= 15
        return {"healthy": self.capture_healthy and fresh and not self.error,
                "mode": "enforce" if self.mode == "enforce" and self.config["enforcement_validated"]
                        and self.capture_healthy and fresh and not self.error and self.firewall is not None else "monitor",
                "enforcement_allowed": self.config["enforcement_validated"],
                "capture_healthy": self.capture_healthy, "capture_epoch": self.capture_epoch,
                "checkpoint_utc": self.checkpoint, "last_evidence_utc": utc(self.last_evidence) if self.last_evidence else None,
                "matched": sum(counts.values()), "unresolved": self.unresolved,
                "proposed": counts.get("proposed", 0),
                "active_bans": sum(until > now and self.applied_monotonic.get(ip, 0) > self.monotonic()
                                   for ip, until in self.applied_until.items()),
                "error": self.error[:500], **{key: self.config[key] for key in ("stream_id", "backend_id", "computer")}}

    def results(self):
        # One current row per client; native decision/proof history stays in SQLite.
        result = [dict(row) for row in self.db.execute("""
            SELECT client_ip,attempts,status,reason,expires FROM (
                SELECT client_ip,attempts,status,reason,expires,timestamp,
                       ROW_NUMBER() OVER (PARTITION BY client_ip ORDER BY timestamp DESC,id DESC) AS rank
                FROM decisions
            ) WHERE rank=1 ORDER BY timestamp DESC LIMIT 100
        """)]
        now = self.clock()
        logical = {row["client_ip"]: row["expires"] for row in
                   self.db.execute("SELECT client_ip,expires FROM bans WHERE expires>?", (now,))}
        for row in result:
            client = row["client_ip"]
            if self.applied_until.get(client, 0) > now and self.applied_monotonic.get(client, 0) > self.monotonic():
                row["status"] = "blocked" if client in logical else "removal_pending"
                row["expires"] = logical.get(client)
            elif client in logical:
                row["status"], row["expires"] = (("whitelisted", None) if self._protected(client)
                                                   else ("suspended", logical[client]))
            elif row["status"] == "removal_pending":
                row["status"] = "removed"
            elif row["status"] == "blocked":
                row["status"], row["expires"] = "expired", None
        return result

    def close(self):
        with self.lock:
            if self.firewall is not None:
                self.firewall.sync({})
            self.db.close()


def make_server(agent):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_args):
            pass  # No XML, credentials, or payloads in HTTP logs.

        def do_POST(self):
            try:
                self.connection.settimeout(5)
                certificate = self.connection.getpeercert(binary_form=True)
                fingerprint = hashlib.sha256(certificate).hexdigest()
                if fingerprint != agent.config["client_sha256"]:
                    raise PermissionError("Client certificate is not enrolled")
                if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                    raise ValueError("A single Content-Length is required")
                size = int(self.headers["Content-Length"])
                if not 0 < size <= MAX_BODY or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    raise ValueError("Invalid request type or size")
                data = self.rfile.read(size)
                if len(data) != size:
                    raise ValueError("Incomplete request body")
                result = agent.handle(self.path, json.loads(data), fingerprint)
                code = 200
            except PermissionError:
                code, result = 403, {"error": "Certificate or stream binding denied"}
            except LookupError:
                code, result = 404, {"error": "Unknown endpoint"}
            except (ValueError, TypeError, KeyError, ET.ParseError):
                code, result = 400, {"error": "Evidence or request validation failed"}
            except Exception:
                LOG.exception("Proxy request failed")
                code, result = 503, {"error": "Proxy agent unavailable"}
            encoded = json.dumps(result).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

    class Server(HTTPServer):
        address_family = socket.AF_INET6 if ipaddress.ip_address(agent.config["api_host"]).version == 6 else socket.AF_INET
        # Handshake happens after accept, with a deadline; an unauthenticated
        # socket cannot indefinitely block an SSL-wrapped listening socket.
        def get_request(self):
            sock, peer = super().get_request()
            sock.settimeout(5)
            try:
                return self.tls.wrap_socket(sock, server_side=True), peer
            except BaseException:
                sock.close()
                raise

        def finish_request(self, request, client_address):
            # Socket timeout bounds inactivity only. A total deadline covers
            # headers and body even if a peer dribbles bytes before every timeout.
            def expire():
                try:
                    request.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                request.close()

            deadline = threading.Timer(REQUEST_DEADLINE_SECONDS, expire)
            deadline.daemon = True
            deadline.start()
            try:
                super().finish_request(request, client_address)
            finally:
                deadline.cancel()

    cfg = agent.config
    server = Server((cfg["api_host"], cfg["api_port"]), Handler, bind_and_activate=False)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=cfg["ca_file"])
    context.load_cert_chain(cfg["cert_file"], cfg["key_file"])
    server.tls = context
    server.server_bind()
    server.server_activate()
    server.timeout = 1
    return server


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"setup", "add", "list", "status", "doctor", "unconfigure", "rotate-logs"}:
        from .proxy_setup import main as setup_main
        return setup_main(argv)
    parser = argparse.ArgumentParser(description=__doc__,
        epilog="Management: rdpguard-proxy setup | add | list | status | doctor | unconfigure")
    parser.add_argument("--config", required=True)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args(argv)
    config = load_config(json.loads(Path(args.config).read_text(encoding="utf-8")))
    if args.check_config:
        print(json.dumps({"valid": True, "stream_id": config["stream_id"],
                          "enforcement_allowed": config["enforcement_validated"]}))
        return 0
    if os.name != "posix" or not Path("/proc/sys/kernel/random/boot_id").exists():
        parser.error("Proxy agent requires Linux")
    from .proxy_capture import ContinuousCapture
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    capture = ContinuousCapture(config, stop)
    # One process owns this scoped state/firewall. A duplicate systemd/manual
    # launch must not race set replacement or share replay counters.
    import fcntl
    state_lock = open(config["state_file"] + ".lock", "a")
    try:
        fcntl.flock(state_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        state_lock.close()
        parser.error("Another proxy agent owns this state file")
    agent = Agent(config, capture)
    if config["enforcement_validated"]:
        agent.firewall = LeasedFirewall(config)
    server = make_server(agent)
    capture.start()
    logging.basicConfig(level=logging.INFO)
    try:
        while not stop.is_set():
            server.handle_request()
            try:
                agent.tick()
            except Exception:
                agent.error = "Agent safety tick failed; enforcement suspended"
                agent.mode = "monitor"
                LOG.exception("Agent safety tick failed")
    finally:
        stop.set()
        server.server_close()
        capture.join(timeout=15)
        agent.close()
        state_lock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
