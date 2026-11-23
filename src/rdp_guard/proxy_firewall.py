"""Listener-scoped nftables planning and explicitly opted-in Linux execution.

This is an internal enforcement adapter, not a network API accepting IP bans.
Only the local evidence/policy engine may supply its complete desired state.
Monitor mode never invokes nft. Native Linux/Docker packet-path validation is
still required before setting the local ``enforcement_approved`` switch.

The owned inet prerouting chain runs at -150, before standard DNAT (-100),
matching the public destination rather than a mutable Docker container address.
It drops only the explicitly configured address, port and published protocols.
Other firewall tables/chains are never flushed or modified. Existing stream
packets from a banned IP are dropped too; this is not a SYN-only restriction.

References: https://netfilter.org/projects/nftables/manpage.html and
https://docs.docker.com/engine/network/firewall-nftables/ .
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
import subprocess
import sys
import threading
import time
from typing import Callable, Iterable


class ProxyFirewallError(RuntimeError):
    pass


def _ip(value: str):
    if not isinstance(value, str) or "%" in value or "/" in value:
        raise ValueError("Expected one literal IP address, without a network or scope")
    address = ipaddress.ip_address(value)
    if (address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local
            or str(address) == "255.255.255.255"
            or (address.version == 6 and address.ipv4_mapped)):
        raise ValueError("Expected a concrete unicast IP address")
    return address


def _integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"Invalid {name}")


def _finite(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"Invalid {name}")
    return float(value)


@dataclass(frozen=True)
class ProxyFirewallConfig:
    stream_id: str
    listener_ip: str
    listener_port: int
    protocols: tuple[str, ...] = ("tcp",)
    whitelist: tuple[str, ...] = ()
    enforcement_approved: bool = False
    max_entries: int = 4000
    max_new_bans_per_minute: int = 20
    max_ttl_seconds: int = 3600
    min_sync_interval_seconds: float = 1.0

    def __post_init__(self):
        if not isinstance(self.stream_id, str) or not 1 <= len(self.stream_id) <= 128:
            raise ValueError("Invalid stream identity")
        object.__setattr__(self, "listener_ip", str(_ip(self.listener_ip)))
        _integer(self.listener_port, 1, 65535, "listener port")
        if (not isinstance(self.protocols, (tuple, list)) or not self.protocols
                or any(p not in ("tcp", "udp") for p in self.protocols)):
            raise ValueError("Explicit published TCP/UDP protocols are required")
        object.__setattr__(self, "protocols", tuple(sorted(set(self.protocols))))
        if type(self.enforcement_approved) is not bool:
            raise ValueError("Local enforcement approval must be a boolean")
        _integer(self.max_entries, 1, 10000, "entry limit")
        _integer(self.max_new_bans_per_minute, 1, 1000, "new-ban rate limit")
        _integer(self.max_ttl_seconds, 1, 604800, "maximum TTL")
        interval = _finite(self.min_sync_interval_seconds, "sync interval")
        if not 0.1 <= interval <= 60:
            raise ValueError("Sync interval must be between 0.1 and 60 seconds")
        if not isinstance(self.whitelist, (tuple, list)) or len(self.whitelist) > 1000:
            raise ValueError("Invalid whitelist")
        networks = []
        for value in self.whitelist:
            if not isinstance(value, str) or "%" in value:
                raise ValueError("Invalid whitelist network")
            networks.append(ipaddress.ip_network(value, strict=True))
        collapsed = []
        for version in (4, 6):
            collapsed.extend(ipaddress.collapse_addresses(n for n in networks if n.version == version))
        object.__setattr__(self, "whitelist", tuple(str(n) for n in collapsed))

    @property
    def table_name(self) -> str:
        digest = hashlib.sha256(self.stream_id.encode("utf-8")).hexdigest()[:24]
        return f"rdpg_proxy_{digest}"

    @property
    def ownership_marker(self) -> str:
        # A changed scope/whitelist must not silently take over an old table.
        immutable = [self.stream_id, self.listener_ip, self.listener_port, self.protocols,
                     self.whitelist, self.max_entries, self.max_ttl_seconds]
        digest = hashlib.sha256(json.dumps(immutable, separators=(",", ":")).encode()).hexdigest()
        return f"rdpguard-proxy:v1:{digest}"


@dataclass(frozen=True)
class ProxyBan:
    client_ip: str
    expires_at: float


@dataclass(frozen=True)
class ProxyFirewallPlan:
    table_name: str
    ownership_marker: str
    script: str
    bans: tuple[ProxyBan, ...]
    whitelisted: tuple[str, ...]
    expired: tuple[str, ...]


@dataclass(frozen=True)
class ProxyFirewallResult:
    applied: bool
    reason: str
    plan: ProxyFirewallPlan | None = None


def build_plan(config: ProxyFirewallConfig, bans: Iterable[ProxyBan], *, now: float,
               table_exists: bool = False) -> ProxyFirewallPlan:
    """Build a bounded transaction; construction never executes commands.

    Expiry is absolute. Repeated full-state synchronization therefore cannot
    refresh a ban indefinitely. Fractional seconds are rounded down, not up.
    """
    now = _finite(now, "current time")
    trusted = tuple(ipaddress.ip_network(n) for n in config.whitelist)
    wanted: dict[str, ProxyBan] = {}
    whitelist, expired = set(), set()
    for index, ban in enumerate(bans):
        if index >= config.max_entries:
            raise ValueError("Desired ban input exceeds entry limit")
        if not isinstance(ban, ProxyBan):
            raise ValueError("Expected internal ProxyBan records")
        address = _ip(ban.client_ip)
        if address.version != ipaddress.ip_address(config.listener_ip).version:
            raise ValueError("Client and public listener address families must match")
        ip = str(address)
        expiry = _finite(ban.expires_at, "ban expiry")
        if ip in wanted:
            raise ValueError("Duplicate desired client IP")
        if any(address in n for n in trusted if n.version == address.version):
            whitelist.add(ip)
            continue
        if expiry - now < 1:
            expired.add(ip)
            continue
        if expiry - now > config.max_ttl_seconds:
            raise ValueError("Ban exceeds finite maximum TTL")
        wanted[ip] = ProxyBan(ip, expiry)
    ordered = tuple(wanted[ip] for ip in sorted(wanted, key=ipaddress.ip_address))
    table, marker = config.table_name, config.ownership_marker
    lines = []
    if not table_exists:
        # create, not add: a concurrently-created table is never merged into.
        lines.append(f'create table inet {table} {{ comment "{marker}"; }}')
        for version in (4, 6):
            lines.append(f'add set inet {table} banned{version} {{ type ipv{version}_addr; '
                         f'flags timeout; size {config.max_entries}; comment "{marker}"; }}')
            networks = [n for n in trusted if n.version == version]
            elements = " elements = { " + ", ".join(map(str, networks)) + " };" if networks else ""
            lines.append(f'add set inet {table} trusted{version} {{ type ipv{version}_addr; '
                         f'flags interval; comment "{marker}";{elements} }}')
        lines.append(f'add chain inet {table} ingress {{ type filter hook prerouting priority -150; '
                     f'policy accept; comment "{marker}"; }}')
        version = ipaddress.ip_address(config.listener_ip).version
        family = "ip" if version == 4 else "ip6"
        for protocol in config.protocols:
            scope = f"{family} daddr {config.listener_ip} {protocol} dport {config.listener_port}"
            lines.append(f'add rule inet {table} ingress {scope} {family} saddr @trusted{version} '
                         f'return comment "{marker}"')
            lines.append(f'add rule inet {table} ingress {scope} {family} saddr @banned{version} '
                         f'counter drop comment "{marker}"')
    else:
        # Preserve owned chains, whitelist and counters; replace only our sets.
        lines.extend(f"flush set inet {table} banned{version}" for version in (4, 6))
    for version in (4, 6):
        elements = [f"{b.client_ip} timeout {math.floor(b.expires_at - now)}s" for b in ordered
                    if ipaddress.ip_address(b.client_ip).version == version]
        if elements:
            lines.append(f"add element inet {table} banned{version} {{ {', '.join(elements)} }}")
    return ProxyFirewallPlan(table, marker, "\n".join(lines) + "\n", ordered,
                             tuple(sorted(whitelist)), tuple(sorted(expired)))


class ScopedNftFirewall:
    """Single-writer, locally configured nft adapter; all subprocesses avoid a shell.

    The service must run one privileged writer per stream. Ownership inspection
    is not protection against a concurrent root administrator changing nftables.
    A failed transaction leaves previous kernel TTLs in place, never indefinite.
    """

    def __init__(self, config: ProxyFirewallConfig, *, runner: Callable = subprocess.run,
                 nft_path: str = "/usr/sbin/nft", clock: Callable = time.time,
                 monotonic: Callable = time.monotonic):
        if not isinstance(nft_path, str) or not nft_path.startswith("/"):
            raise ValueError("nft executable must be an absolute path")
        self.config, self.runner, self.nft_path = config, runner, nft_path
        self.clock, self.monotonic = clock, monotonic
        self._lock = threading.RLock()
        self._recent_additions = deque()
        self._applied: dict[str, float] = {}
        self._last_sync: float | None = None

    def _command(self, args, *, script=None):
        try:
            result = self.runner([self.nft_path, *args], input=script, capture_output=True,
                                 text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProxyFirewallError(f"nft execution failed: {exc}") from exc
        if result.returncode:
            raise ProxyFirewallError(f"nft rejected operation: {result.stderr[:1000]}")
        return result.stdout

    def _json(self, args):
        try:
            result = json.loads(self._command(["-j", *args]))
            if not isinstance(result, dict) or not isinstance(result.get("nftables"), list):
                raise ValueError("Expected nftables object list")
            return result["nftables"]
        except (ValueError, TypeError) as exc:
            raise ProxyFirewallError("Invalid nft read-back JSON") from exc

    def _owned_table(self):
        tables = [obj["table"] for obj in self._json(["list", "tables"])
                  if isinstance(obj, dict) and "table" in obj
                  and obj["table"].get("family") == "inet"
                  and obj["table"].get("name") == self.config.table_name]
        if not tables:
            return None
        if len(tables) != 1:
            raise ProxyFirewallError("Ambiguous nft table ownership")
        objects = self._json(["list", "table", "inet", self.config.table_name])
        self._validate_owned(objects)
        return objects

    def _validate_owned(self, objects):
        expected_sets = {"banned4", "banned6", "trusted4", "trusted6"}
        sets, tables, chains, rules = set(), 0, 0, 0
        rule_signatures = set()
        for obj in objects:
            if not isinstance(obj, dict) or len(obj) != 1:
                raise ProxyFirewallError("Malformed owned table read-back")
            kind, item = next(iter(obj.items()))
            if kind == "metainfo":
                continue
            if kind not in {"table", "chain", "set", "rule"} or not isinstance(item, dict):
                raise ProxyFirewallError("Unexpected object in owned table")
            if (item.get("family") != "inet" or item.get("comment") != self.config.ownership_marker
                    or (item.get("name") if kind == "table" else item.get("table"))
                    != self.config.table_name):
                raise ProxyFirewallError("Refusing foreign nft table or object ownership")
            if kind == "table":
                tables += 1
            elif kind == "set":
                name = item.get("name")
                if name not in expected_sets or name in sets:
                    raise ProxyFirewallError("Unexpected owned set")
                version = name[-1]
                flags = ["timeout"] if name.startswith("banned") else ["interval"]
                if item.get("type") != f"ipv{version}_addr" or item.get("flags") != flags:
                    raise ProxyFirewallError("Owned set schema changed")
                sets.add(name)
            elif kind == "chain":
                chains += 1
                if (item.get("name"), item.get("type"), item.get("hook"), item.get("prio"),
                        item.get("policy")) != ("ingress", "filter", "prerouting", -150, "accept"):
                    raise ProxyFirewallError("Owned chain scope changed")
            elif kind == "rule":
                rules += 1
                if item.get("chain") != "ingress":
                    raise ProxyFirewallError("Unexpected owned rule chain")
                signature = self._rule_signature(item)
                if signature in rule_signatures:
                    raise ProxyFirewallError("Duplicate owned rule")
                rule_signatures.add(signature)
        if tables != 1 or chains != 1 or sets != expected_sets or rules != 2 * len(self.config.protocols):
            raise ProxyFirewallError("Incomplete or modified owned table")

    def _rule_signature(self, item):
        """Check the effective selector, not merely a copied ownership comment."""
        expressions = item.get("expr")
        if not isinstance(expressions, list):
            raise ProxyFirewallError("Missing owned rule expressions")
        matches, metadata, verdict, counters = {}, {}, None, 0
        for expression in expressions:
            if not isinstance(expression, dict) or len(expression) != 1:
                raise ProxyFirewallError("Unexpected owned rule expression")
            kind, value = next(iter(expression.items()))
            if kind == "match" and isinstance(value, dict) and value.get("op") in ("==", "in"):
                left, right = value.get("left"), value.get("right")
                if not isinstance(left, dict) or len(left) != 1:
                    raise ProxyFirewallError("Unexpected owned rule match")
                if "payload" in left and isinstance(left["payload"], dict):
                    payload = left["payload"]
                    key = (payload.get("protocol"), payload.get("field"))
                    if key in matches or set(payload) != {"protocol", "field"}:
                        raise ProxyFirewallError("Unexpected owned rule payload")
                    matches[key] = right
                elif "meta" in left and isinstance(left["meta"], dict):
                    key = left["meta"].get("key")
                    if key not in ("nfproto", "l4proto") or key in metadata:
                        raise ProxyFirewallError("Unexpected owned rule metadata")
                    metadata[key] = right
                else:
                    raise ProxyFirewallError("Unexpected owned rule match")
            elif kind in ("return", "drop") and value is None and verdict is None:
                verdict = kind
            elif kind == "counter" and isinstance(value, dict):
                if any(type(v) is not int or v < 0 for v in value.values()):
                    raise ProxyFirewallError("Invalid owned rule counter")
                counters += 1
            else:
                raise ProxyFirewallError("Unexpected owned rule action")
        version = ipaddress.ip_address(self.config.listener_ip).version
        family = "ip" if version == 4 else "ip6"
        prefix = "trusted" if verdict == "return" else "banned"
        for protocol in self.config.protocols:
            expected = {(family, "daddr"): self.config.listener_ip,
                        (protocol, "dport"): self.config.listener_port,
                        (family, "saddr"): f"@{prefix}{version}"}
            if (matches == expected and verdict in ("return", "drop")
                    and counters == (1 if verdict == "drop" else 0)
                    and metadata.get("nfproto", f"ipv{version}") == f"ipv{version}"
                    and metadata.get("l4proto", protocol) == protocol):
                return protocol, verdict
        raise ProxyFirewallError("Owned rule listener scope changed")

    def _members(self, objects):
        members = set()
        for obj in objects:
            item = obj.get("set", {})
            if item.get("name") not in ("banned4", "banned6"):
                continue
            for element in item.get("elem", []):
                if not isinstance(element, dict) or not isinstance(element.get("elem"), dict):
                    raise ProxyFirewallError("Banned element has no finite timeout")
                value = element["elem"]
                timeout = value.get("timeout")
                if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                        or not 0 < timeout <= self.config.max_ttl_seconds):
                    raise ProxyFirewallError("Banned element has no finite timeout")
                try:
                    members.add(str(_ip(value["val"])))
                except (ValueError, KeyError, TypeError) as exc:
                    raise ProxyFirewallError("Invalid owned ban element") from exc
        return members

    def _authorize(self, mode):
        if mode not in ("monitor", "enforce"):
            raise ValueError("Mode must be monitor or enforce")
        if mode == "enforce":
            if not self.config.enforcement_approved:
                raise ProxyFirewallError("Enforcement requires explicit local approval after native validation")
            if not sys.platform.startswith("linux"):
                raise ProxyFirewallError("Native nft execution requires Linux")

    def sync(self, bans: Iterable[ProxyBan], *, mode: str = "monitor", now: float | None = None):
        self._authorize(mode)
        now = self.clock() if now is None else now
        plan = build_plan(self.config, bans, now=now)
        if mode == "monitor":
            return ProxyFirewallResult(False, "monitor_only", plan)
        with self._lock:
            tick = self.monotonic()
            desired = {ban.client_ip: ban.expires_at for ban in plan.bans}
            previous = {ip for ip, expiry in self._applied.items() if expiry > now}
            new = set(desired) - previous
            while self._recent_additions and self._recent_additions[0][0] <= tick - 60:
                self._recent_additions.popleft()
            if len(self._recent_additions) + len(new) > self.config.max_new_bans_per_minute:
                raise ProxyFirewallError("New-ban rate limit exceeded")
            # Removal-only reconciliation is never held up by the write throttle.
            removal_only = set(desired) < previous and all(
                expiry <= self._applied[ip] for ip, expiry in desired.items())
            if (not removal_only and self._last_sync is not None
                    and tick - self._last_sync < self.config.min_sync_interval_seconds):
                raise ProxyFirewallError("Firewall sync rate limit exceeded")
            existing = self._owned_table()
            plan = build_plan(self.config, plan.bans, now=now, table_exists=existing is not None)
            self._command(["-c", "-f", "-"], script=plan.script)
            # Ownership reads and nft --check may take time. Never give a stale
            # absolute expiry a fresh full timeout when the transaction applies.
            elapsed = max(0, self.monotonic() - tick)
            plan = build_plan(self.config, plan.bans, now=now + elapsed,
                              table_exists=existing is not None)
            desired = {ban.client_ip: ban.expires_at for ban in plan.bans}
            new &= set(desired)
            # Charge attempted writes too: a timeout/read-back failure must not
            # turn retries into an unbounded stream of newly banned addresses.
            self._recent_additions.extend((tick, ip) for ip in new)
            self._last_sync = tick
            self._command(["-f", "-"], script=plan.script)
            actual = self._owned_table()
            if actual is None or self._members(actual) != set(desired):
                raise ProxyFirewallError("Firewall read-back differs from desired bans")
            self._applied = desired
            return ProxyFirewallResult(True, "applied", plan)

    def remove(self, *, mode: str = "monitor"):
        """Explicit cleanup removes this owned table only, including all its bans."""
        self._authorize(mode)
        if mode == "monitor":
            return ProxyFirewallResult(False, "monitor_only")
        with self._lock:
            if self._owned_table() is None:
                return ProxyFirewallResult(False, "already_absent")
            script = f"delete table inet {self.config.table_name}\n"
            self._command(["-c", "-f", "-"], script=script)
            self._command(["-f", "-"], script=script)
            if self._owned_table() is not None:
                raise ProxyFirewallError("Owned table removal failed read-back")
            self._applied.clear()
            return ProxyFirewallResult(True, "removed")
