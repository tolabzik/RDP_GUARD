"""Offline, non-enforcing correlation of Windows and reverse-proxy evidence.

This module never creates firewall rules or contacts either machine. A demonstrated
candidate is a relationship observed in the supplied capture, not an authorization
to ban an address. In particular, native ActivityID provenance and continuous
connection generations still require validation before any enforcing integration.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re
import uuid


CHANNEL = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
PROVIDER = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS"
PROVIDER_GUID = "1139c61b-b549-4251-8ed3-27250a1edec8"
WINDOWS_SCHEMA = "rdpguard.windows-proxy-evidence.v1"
LIMITATIONS = [
    "Offline evidence only; inputs are not authenticated and no firewall action is authorized.",
    "ActivityID linkage is empirical for the captured Windows build, not proof against client-controlled IDs.",
    "Clock bounds, event loss outside the capture, and connection reuse outside the capture are not proven.",
    "A conntrack snapshot proves an observed tuple mapping, not its complete lifecycle.",
    "Nginx process identities are sampled; a worker never observed in process metadata cannot be correlated.",
    "Any additional source IP/port translation between the recorded backend and Windows must be accounted for; "
    "an unchanged proxy IP alone does not prove source-port preservation.",
]
LOG_RE = re.compile(
    r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
    r"\[(?P<level>\w+)\] (?P<pid>\d+)#\d+: \*(?P<id>\d+) (?P<text>.*)$"
)
CONNECT_RE = re.compile(r"^(client|proxy) (\S+) connected to (\S+)(?:,.*)?$")
DISCONNECT_RE = re.compile(r"^(?:client|upstream) disconnected(?:,.*)?$")


def instant(value: str) -> float:
    if not isinstance(value, str):
        raise ValueError("Timestamp must be an ISO-8601 string")
    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("Timestamp must include a UTC offset")
    return value.timestamp()


def ip(value: str) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Expected an IP without a scope identifier")
    result = ipaddress.ip_address(value)
    return str(result.ipv4_mapped or result) if result.version == 6 else str(result)


def integer(value, low=0, high=2**63-1) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Expected an integer in range")
    return value


def guid(value: str) -> str:
    result = uuid.UUID(value.strip("{}"))
    if not result.int:
        raise ValueError("Empty ActivityID")
    return str(result)


def endpoint(value) -> tuple[str, int]:
    if isinstance(value, dict):
        return ip(value["ip"]), integer(value["port"], 1, 65535)
    if not isinstance(value, str):
        raise ValueError("Expected an IP:port endpoint")
    if value.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d+)", value)
        if not match:
            raise ValueError("Invalid bracketed endpoint")
        host, port = match.groups()
    else:
        host, separator, port = value.rpartition(":")
        if not separator or ":" in host or not port.isdigit():
            raise ValueError("IPv6 endpoints require brackets")
    return ip(host), integer(int(port), 1, 65535)


def flow_tuple(value: dict) -> tuple[str, int, str, int, int]:
    return (ip(value["src"]), integer(value["sport"], 1, 65535), ip(value["dst"]),
            integer(value["dport"], 1, 65535), integer(value["protocol"], 0, 255))


def named_data(value) -> dict:
    if isinstance(value, dict):
        return value
    result = {}
    for item in value:
        if item["name"] in result:
            raise ValueError("Duplicate native event data field")
        result[item["name"]] = item["value"]
    return result


@dataclass
class Connection:
    key: tuple[str, int, int]
    client: tuple[str, int] | None = None
    listener: tuple[str, int] | None = None
    upstream: tuple[str, int] | None = None
    backend: tuple[str, int] | None = None
    accepted: float | None = None
    connected: float | None = None
    closed: float | None = None
    lines: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def tuple(self):
        if self.upstream and self.backend:
            return (*self.upstream, *self.backend, 6)
        return None

    def complete(self, start, end):
        values = (self.accepted, self.connected, self.closed)
        return (not self.errors and self.client and self.listener and self.upstream and self.backend
                and all(value is not None for value in values)
                and start <= self.accepted <= self.connected <= self.closed < end)


def read_linux(records: list[dict]) -> tuple[dict, list[Connection], list[dict], list[str]]:
    starts = [r for r in records if r.get("kind") == "capture_start"]
    ends = [r for r in records if r.get("kind") == "capture_end"]
    if len(starts) != 1 or len(ends) != 1:
        raise ValueError("Linux capture requires exactly one start and end")
    metadata = starts[0]
    capture_id = str(metadata["capture_id"])
    if not capture_id:
        raise ValueError("Missing capture epoch")
    start, end = instant(metadata["observed_utc"]), instant(ends[0]["observed_utc"])
    if end <= start:
        raise ValueError("Invalid Linux capture window")
    offset = integer(metadata["nginx_utc_offset_minutes"], -1439, 1439)
    log_zone = timezone(timedelta(minutes=offset))
    issues = []
    if ends[0].get("complete") is not True:
        issues.append("linux_capture_incomplete")
    if metadata.get("errors") or ends[0].get("errors") or ends[0].get("gaps"):
        issues.append("linux_capture_reported_errors")
    connections = {}
    nat = []
    process_identities = {}
    process_namespace = metadata.get("nginx_pid_namespace")
    if not isinstance(process_namespace, str) or not process_namespace:
        issues.append("missing_nginx_pid_namespace")

    def observe_processes(items, *, allow_new=True):
        for item in items:
            try:
                if item["pid_namespace"] != process_namespace:
                    raise ValueError("Process belongs to another PID namespace")
                log_pid = integer(item["namespace_pids"][-1], 1)
                identity = (integer(item["host_pid"], 1), integer(item["start_ticks"]))
                if log_pid not in process_identities and not allow_new:
                    issues.append("removed_nginx_process_was_not_observed")
                elif log_pid in process_identities and process_identities[log_pid] != identity:
                    issues.append("nginx_namespace_pid_reused")
                else:
                    process_identities[log_pid] = identity
            except (KeyError, ValueError, TypeError, IndexError):
                issues.append("invalid_nginx_process_identity")

    observe_processes(metadata.get("nginx_processes", []))
    for record in records:
        if record.get("capture_id") != capture_id:
            issues.append("mixed_capture_epochs")
            continue
        kind = record.get("kind")
        if kind == "gap":
            issues.append("linux_capture_gap:" + str(record.get("reason", "unknown")))
        elif kind in ("nginx_process_change", "nginx_process_snapshot"):
            if record.get("pid_namespace") != process_namespace:
                issues.append("mixed_nginx_pid_namespaces")
                continue
            if kind == "nginx_process_change":
                observe_processes(record.get("added", []))
                # Removed identities remain known for the entire capture: graceful
                # draining or worker exit must not invalidate already observed flows.
                observe_processes(record.get("removed", []), allow_new=False)
            else:
                observe_processes(record.get("nginx_processes", []))
        elif kind == "conntrack":
            try:
                original, reply = flow_tuple(record["original"]), flow_tuple(record["reply"])
                observed = instant(record["observed_utc"])
                if not start <= observed <= end or original[4] != 6 or reply[4] != 6:
                    raise ValueError("Invalid TCP conntrack observation")
                if record.get("operation") not in ("snapshot", "new", "update", "destroy"):
                    raise ValueError("Unknown conntrack observation kind")
                integer(record.get("zone", 0), 0, 65535)
                if record.get("conntrack_id") is not None:
                    integer(record["conntrack_id"], 0, 2**32-1)
                nat.append({"original": original, "reply": reply, "observed": observed,
                            "operation": record.get("operation"), "record": record})
            except (KeyError, ValueError, TypeError):
                issues.append("invalid_conntrack_record")
        elif kind == "nginx_line":
            line = record.get("line", "")
            match = LOG_RE.match(line)
            if not match:
                continue
            key = (capture_id, int(match["pid"]), int(match["id"]))
            connection = connections.setdefault(key, Connection(key))
            timestamp = datetime.strptime(match["time"], "%Y/%m/%d %H:%M:%S").replace(
                tzinfo=log_zone).timestamp()
            message = match["text"]
            step = CONNECT_RE.match(message)
            if step:
                connection.lines.append(line)
                try:
                    source, target = endpoint(step[2]), endpoint(step[3])
                    if step[1] == "client":
                        if connection.accepted is not None:
                            connection.errors.append("duplicate_accept_or_reused_process_id")
                        connection.client, connection.listener, connection.accepted = source, target, timestamp
                    else:
                        if connection.connected is not None:
                            connection.errors.append("upstream_retry_or_duplicate_connect")
                        connection.upstream, connection.backend, connection.connected = source, target, timestamp
                except (ValueError, TypeError, KeyError):
                    connection.errors.append("invalid_nginx_endpoint")
            elif DISCONNECT_RE.match(message):
                connection.lines.append(line)
                if connection.closed is not None:
                    connection.errors.append("duplicate_disconnect")
                connection.closed = timestamp
            elif any(term in message for term in ("connect() failed", "timed out", "no live upstreams")):
                connection.errors.append("nginx_connection_error")
    for connection in connections.values():
        if connection.key[1] not in process_identities:
            connection.errors.append("unknown_nginx_process_identity")
    metadata = dict(metadata, _start=start, _end=end)
    return metadata, list(connections.values()), nat, sorted(set(issues))


def read_windows(document: dict) -> tuple[list[dict], list[str]]:
    if document.get("schema") != WINDOWS_SCHEMA:
        raise ValueError("Unsupported Windows evidence schema")
    start, end = instant(document["requested_start_utc"]), instant(document["requested_end_utc"])
    query_start = instant(document["query_start_utc"])
    if not query_start <= start < end:
        raise ValueError("Invalid Windows query window")
    issues = []
    if document.get("complete") is not True or document.get("truncated") is not False or document.get("errors"):
        issues.append("windows_export_incomplete")
    events, seen = [], {}
    for raw in document["events"]:
        try:
            if (raw["channel"] != CHANNEL or raw["provider_name"] != PROVIDER
                    or guid(raw["provider_guid"]) != PROVIDER_GUID):
                raise ValueError("Unexpected event provenance")
            event_id = integer(raw["event_id"])
            if event_id not in (131, 140) or integer(raw["version"]) != 0:
                raise ValueError("Unsupported native event schema")
            timestamp = instant(raw["timestamp_utc"])
            if not query_start <= timestamp < end or (event_id == 140 and timestamp < start):
                raise ValueError("Event outside declared export window")
            computer = raw["computer"]
            if not isinstance(computer, str) or not computer.strip():
                raise ValueError("Missing Windows computer identity")
            record_id = integer(raw["record_id"], 1)
            activity = guid(raw["activity_id"])
            data = named_data(raw["data"])
            event = dict(raw, _time=timestamp, _activity=activity, _data=data,
                         _requested=start <= timestamp < end)
            if event_id == 131:
                if data.get("ConnType") != "TCP":
                    raise ValueError("Only native TCP connections are supported")
                event["_peer"] = endpoint(data["ClientIP"])
            else:
                event["_failure_ip"] = ip(data["IPString"])
            key = (computer.casefold(), record_id)
            canonical = json.dumps(raw, sort_keys=True)
            if key in seen:
                if seen[key] != canonical:
                    issues.append("windows_record_conflict_or_log_reset")
                continue
            seen[key] = canonical
            events.append(event)
        except (KeyError, ValueError, TypeError, AttributeError):
            issues.append("invalid_windows_event")
    computers = {event["computer"].casefold() for event in events}
    if len(computers) > 1:
        issues.append("multiple_windows_hosts_for_single_backend")
    return events, sorted(set(issues))


def correlate_evidence(windows_export: dict, linux_records: list[dict]) -> dict:
    """Return observed candidates and explicit rejection reasons; never enforce."""
    capture, connections, nat, issues = read_linux(linux_records)
    events, windows_issues = read_windows(windows_export)
    issues.extend(windows_issues)
    target = endpoint(capture["backend"])
    listener_port = integer(capture["listener"]["port"], 1, 65535)
    listener_ip = capture["listener"].get("ip")
    if listener_ip is not None:
        listener_ip = ip(listener_ip)
    connection_index = defaultdict(list)
    for connection in connections:
        if connection.tuple:
            connection_index[connection.tuple].append(connection)
    activity_index = defaultdict(list)
    for event in events:
        if event["event_id"] == 131:
            activity_index[(event["computer"].casefold(), event["_activity"])].append(event)
    nat_index = defaultdict(list)
    for observation in nat:
        reply = observation["reply"]
        if (reply[0], reply[1]) == target:
            nat_index[(reply[2], reply[3])].append(observation)
    results = []
    for failure in sorted(events, key=lambda e: (e["_time"], e["record_id"])):
        if failure["event_id"] != 140:
            continue
        result = {"status": "unresolved", "computer": failure["computer"],
                  "failure_record_id": failure["record_id"], "failure_timestamp_utc": failure["timestamp_utc"],
                  "activity_id": failure["_activity"], "proxy_ip": failure["_failure_ip"]}
        results.append(result)
        if issues:
            result["reason"] = "incomplete_or_invalid_capture"
            continue
        starts = activity_index[(failure["computer"].casefold(), failure["_activity"])]
        if len(starts) != 1:
            result["reason"] = "missing_connection_event" if not starts else "ambiguous_activity_id"
            continue
        start = starts[0]
        peer = start["_peer"]
        if start["record_id"] >= failure["record_id"] or start["_time"] > failure["_time"]:
            result["reason"] = "windows_event_order_conflict"
            continue
        if peer[0] != failure["_failure_ip"]:
            result["reason"] = "windows_failure_ip_mismatch"
            continue
        observations = nat_index[peer]
        matches = {}
        rejected = set()
        outside_lifetime = False
        for observation in observations:
            original = observation["original"]
            if (original[2], original[3]) != target:
                rejected.add("unexpected_nat_destination")
                continue
            generations = connection_index[original]
            if len(generations) > 1:
                rejected.add("reused_upstream_tuple")
                continue
            if not generations:
                rejected.add("missing_nginx_connection")
                continue
            connection = generations[0]
            if not connection.complete(capture["_start"], capture["_end"]):
                rejected.add("unknown_nginx_process_identity" if "unknown_nginx_process_identity"
                             in connection.errors else "incomplete_nginx_lifecycle")
                continue
            if connection.listener[1] != listener_port or (listener_ip is not None
                    and connection.listener[0] not in (listener_ip, "0.0.0.0", "::")):
                rejected.add("unexpected_nginx_listener")
                continue
            # Nginx INFO timestamps have one-second resolution. This is a
            # consistency bound after matching exact endpoints, never nearest-time selection.
            if not (connection.connected <= start["_time"] <= failure["_time"] < connection.closed + 1
                    and connection.connected <= observation["observed"] < connection.closed + 1):
                outside_lifetime = True
                continue
            matches.setdefault(connection.key, (connection, observation))
        # A visible tuple mapped to more than one original tuple is ambiguous,
        # even if selecting the nearest timestamp would appear convenient.
        nat_generations = {(item["record"].get("zone", 0), item["record"].get("conntrack_id"))
                           for item in observations}
        if (len({observation["original"] for observation in observations}) > 1
                or len(nat_generations) > 1):
            result["reason"] = "reused_or_ambiguous_nat_tuple"
        elif len(matches) != 1 or rejected:
            result["reason"] = ("ambiguous_proxy_connections" if len(matches) > 1 else
                                ",".join(sorted(rejected)) if rejected else
                                "connection_lifetime_mismatch" if outside_lifetime else "missing_nat_mapping")
        else:
            connection, observation = next(iter(matches.values()))
            result.update(status="demonstrated_candidate", reason="exact_endpoints_with_observed_activity_link",
                          client_ip=connection.client[0], client_port=connection.client[1],
                          connection_record_id=start["record_id"], proxy_peer={"ip": peer[0], "port": peer[1]},
                          nginx_connection={"capture_id": connection.key[0], "worker_pid": connection.key[1],
                                            "connection_id": connection.key[2], "lines": connection.lines},
                          nat_observation=observation["record"])
    return {"schema": "rdpguard.proxy-shadow-report.v1", "shadow_only": True,
            "enforcement_supported": False, "capture_id": capture["capture_id"],
            "issues": sorted(set(issues)), "limitations": LIMITATIONS,
            "counts": {"failures": len(results), "demonstrated_candidates": sum(
                result["status"] == "demonstrated_candidate" for result in results)}, "results": results}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows", type=Path, required=True, help="Windows export JSON")
    parser.add_argument("--linux", type=Path, required=True, help="Linux capture JSONL")
    args = parser.parse_args(argv)
    try:
        windows = json.loads(args.windows.read_text(encoding="utf-8-sig"))
        linux = [json.loads(line) for line in args.linux.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        report = correlate_evidence(windows, linux)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(2, f"Cannot analyze evidence: {exc}\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
