#!/usr/bin/env python3
"""Opt-in native nftables acceptance in disposable Linux network namespaces.

CI: sudo "$(command -v python)" scripts/Test-ProxyFirewall-Linux.py --run
Requires Linux root, iproute2 and nftables. Without --run this only prints help.
All routes, interfaces, forwarding settings and firewall rules are created inside
three uniquely named namespaces and removed in finally. The default host's
firewall/sysctls/routes are never changed. No production address is contacted.

This tests an IPv4 pre-DNAT path resembling a published Docker port. It does not
run Docker/NPM, test IPv6 packets, or validate Windows ActivityID attribution.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid


source = Path(__file__).resolve().parents[1] / "src"
if (source / "rdp_guard" / "proxy_firewall.py").is_file():
    sys.path.insert(0, str(source))

from rdp_guard.proxy_firewall import (  # noqa: E402
    ProxyBan, ProxyFirewallConfig, ProxyFirewallError, ScopedNftFirewall,
)


PUBLIC = "192.0.2.45"
OTHER_PUBLIC = "192.0.2.46"
CLIENT = "10.233.11.2"
OTHER_CLIENT = "10.233.11.3"
TRUSTED_CLIENT = "10.233.11.4"
BACKEND = "10.233.12.2"
PUBLIC_PORT = 45451
OTHER_PORT = 45452
BACKEND_PORT = 3389
NAT_TABLE = "rdpg_acceptance_nat"

SERVER_CODE = r"""
import json, socket, sys, threading
host, port = sys.argv[1], int(sys.argv[2])
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind((host, port))
tcp.listen(32)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind((host, port))
def echo_udp():
    while True:
        data, peer = udp.recvfrom(4096)
        udp.sendto(data, peer)
threading.Thread(target=echo_udp, daemon=True).start()
print(json.dumps({'ready': True}), flush=True)
while True:
    conn, peer = tcp.accept()
    with conn:
        conn.settimeout(2)
        try:
            conn.sendall(conn.recv(4096))
        except OSError:
            pass
"""

PROBE_CODE = r"""
import json, socket, sys
source, host, port, protocol, token = sys.argv[1:]
payload = token.encode('ascii')
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
sock.settimeout(0.6)
sock.bind((source, 0))
try:
    sock.connect((host, int(port)))
    sock.sendall(payload)
    received = sock.recv(4096)
    print(json.dumps({'ok': received == payload, 'error': ''}))
except OSError as exc:
    print(json.dumps({'ok': False, 'error': type(exc).__name__}))
finally:
    sock.close()
"""


class AcceptanceError(RuntimeError):
    pass


def run_command(args, *, input=None, timeout=10, check=True):
    result = subprocess.run(args, input=input, capture_output=True, text=True,
                            timeout=timeout, check=False)
    if check and result.returncode:
        raise AcceptanceError(f"Command failed ({result.returncode}): {' '.join(args[:8])}\n"
                              f"{result.stderr[-2000:]}")
    return result


class NamespaceNftRunner:
    """Every production-adapter nft call runs inside the owned proxy namespace."""
    def __init__(self, ip_tool, nft_tool, namespace, *, runner=subprocess.run):
        self.ip_tool, self.nft_tool, self.namespace = ip_tool, nft_tool, namespace
        self.runner = runner

    def __call__(self, args, **kwargs):
        if not args or args[0] != self.nft_tool or kwargs.get("shell"):
            raise AcceptanceError("Only the fixed nft executable may use this namespace runner")
        kwargs["timeout"] = min(kwargs.get("timeout", 10), 10)
        return self.runner([self.ip_tool, "netns", "exec", self.namespace, *args], **kwargs)


class Lab:
    def __init__(self, ip_tool, nft_tool, *, runner=run_command):
        suffix = uuid.uuid4().hex[:12]
        self.names = {role: f"rdpg-fw-{suffix}-{role}" for role in ("client", "proxy", "backend")}
        self.ip_tool, self.nft_tool, self.runner = ip_tool, nft_tool, runner
        self.created = []
        self.server = None
        self.checks = []

    def ns_command(self, role, *args, **kwargs):
        namespace = self.names[role]
        if namespace not in self.created:
            raise AcceptanceError("Refusing command in an unowned namespace")
        return self.runner([self.ip_tool, "netns", "exec", namespace, *map(str, args)], **kwargs)

    def ip_command(self, role, *args):
        namespace = self.names[role]
        if namespace not in self.created:
            raise AcceptanceError("Refusing interface operation in an unowned namespace")
        return self.runner([self.ip_tool, "-n", namespace, *map(str, args)])

    def nft(self, script):
        return self.ns_command("proxy", self.nft_tool, "-f", "-", input=script)

    def setup(self):
        for name in self.names.values():
            self.runner([self.ip_tool, "netns", "add", name])
            self.created.append(name)  # Never delete a pre-existing namespace after a failed add.
        self.ip_command("client", "link", "add", "c0", "type", "veth", "peer", "name", "p0",
                        "netns", self.names["proxy"])
        self.ip_command("proxy", "link", "add", "p1", "type", "veth", "peer", "name", "b0",
                        "netns", self.names["backend"])
        for role in self.names:
            self.ip_command(role, "link", "set", "lo", "up")
        for role, interface, addresses in (
                ("client", "c0", [CLIENT + "/24", OTHER_CLIENT + "/24", TRUSTED_CLIENT + "/24"]),
                ("proxy", "p0", ["10.233.11.1/24"]),
                ("proxy", "p1", ["10.233.12.1/24"]),
                ("backend", "b0", [BACKEND + "/24"])):
            for address in addresses:
                self.ip_command(role, "addr", "add", address, "dev", interface)
            self.ip_command(role, "link", "set", interface, "up")
        for address in (PUBLIC, OTHER_PUBLIC):
            self.ip_command("proxy", "addr", "add", address + "/32", "dev", "lo")
        self.ip_command("client", "route", "add", "192.0.2.0/24", "via", "10.233.11.1")
        self.ip_command("backend", "route", "add", "default", "via", "10.233.12.1")
        # netns exec is mandatory: never set the default host's forwarding state.
        self.ns_command("proxy", sys.executable, "-c",
                        "from pathlib import Path; Path('/proc/sys/net/ipv4/ip_forward').write_text('1\\n')")
        self.nft(f"""
            create table ip {NAT_TABLE}
            add chain ip {NAT_TABLE} prerouting {{ type nat hook prerouting priority -100; policy accept; }}
            add rule ip {NAT_TABLE} prerouting ip daddr {{ {PUBLIC}, {OTHER_PUBLIC} }} tcp dport {{ {PUBLIC_PORT}, {OTHER_PORT} }} counter dnat to {BACKEND}:{BACKEND_PORT}
            add rule ip {NAT_TABLE} prerouting ip daddr {{ {PUBLIC}, {OTHER_PUBLIC} }} udp dport {{ {PUBLIC_PORT}, {OTHER_PORT} }} counter dnat to {BACKEND}:{BACKEND_PORT}
        """)
        self.server = subprocess.Popen(
            [self.ip_tool, "netns", "exec", self.names["backend"], sys.executable, "-u", "-c",
             SERVER_CODE, BACKEND, str(BACKEND_PORT)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready, _, _ = select.select([self.server.stdout], [], [], 5)
        if not ready or self.server.stdout.readline().strip() != '{"ready": true}':
            raise AcceptanceError("Isolated backend echo server did not become ready")

    def probe(self, source=CLIENT, *, host=PUBLIC, port=PUBLIC_PORT, protocol="tcp"):
        response = self.ns_command("client", sys.executable, "-c", PROBE_CODE, source, host, port,
                                   protocol, uuid.uuid4().hex, timeout=3)
        result = json.loads(response.stdout)
        if type(result.get("ok")) is not bool:
            raise AcceptanceError("Invalid isolated probe response")
        return result["ok"]

    def expect(self, name, allowed, *args, **kwargs):
        actual = self.probe(*args, **kwargs)
        if actual is not allowed:
            raise AcceptanceError(f"{name}: expected {'allowed' if allowed else 'blocked'} traffic")
        self.pass_check(name)

    def pass_check(self, name):
        self.checks.append(name)
        print(json.dumps({"check": name, "status": "passed"}), flush=True)

    def table_objects(self, family, name):
        return json.loads(self.ns_command("proxy", self.nft_tool, "-j", "list", "table", family, name).stdout)["nftables"]

    def tables(self):
        rows = json.loads(self.ns_command("proxy", self.nft_tool, "-j", "list", "tables").stdout)["nftables"]
        return {(row["table"]["family"], row["table"]["name"]) for row in rows if "table" in row}

    def counted_packets(self, family, table):
        return sum(expression["counter"].get("packets", 0)
                   for row in self.table_objects(family, table)
                   for expression in row.get("rule", {}).get("expr", []) if "counter" in expression)

    def firewall(self, config):
        return ScopedNftFirewall(config, nft_path=self.nft_tool,
                                 runner=NamespaceNftRunner(self.ip_tool, self.nft_tool, self.names["proxy"]))

    def cleanup(self):
        errors = []
        if self.server is not None:
            try:
                self.server.terminate()
                try:
                    self.server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.server.kill()
                    self.server.wait(timeout=3)
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(f"backend process cleanup: {exc}")
            finally:
                for pipe in (self.server.stdout, self.server.stderr):
                    if pipe is not None:
                        pipe.close()
        for name in reversed(self.created):
            try:
                result = self.runner([self.ip_tool, "netns", "delete", name], check=False)
                if result.returncode:
                    errors.append(f"namespace cleanup failed: {name}: {result.stderr[-500:]}")
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(f"namespace cleanup failed: {name}: {exc}")
        self.created.clear()
        return errors


def acceptance(lab):
    lab.setup()
    config = ProxyFirewallConfig(
        stream_id=lab.names["proxy"], listener_ip=PUBLIC, listener_port=PUBLIC_PORT,
        protocols=("tcp",), whitelist=(TRUSTED_CLIENT + "/32",), enforcement_approved=True,
        max_ttl_seconds=30, min_sync_interval_seconds=0.1)
    firewall = lab.firewall(config)
    lab.expect("baseline_tcp_through_dnat", True)
    lab.expect("baseline_udp_through_dnat", True, protocol="udp")
    now = time.time()
    result = firewall.sync([ProxyBan(CLIENT, now + 30), ProxyBan(TRUSTED_CLIENT, now + 30)],
                           mode="enforce", now=now)
    if result.plan.whitelisted != (TRUSTED_CLIENT,):
        raise AcceptanceError("Trusted client unexpectedly entered desired ban set")
    before = lab.counted_packets("inet", config.table_name)
    nat_before = lab.counted_packets("ip", NAT_TABLE)
    lab.expect("target_tcp_blocked_before_dnat", False)
    if lab.counted_packets("inet", config.table_name) <= before:
        raise AcceptanceError("Owned pre-DNAT drop counter did not increase")
    lab.pass_check("owned_prednat_drop_counter_increased")
    if lab.counted_packets("ip", NAT_TABLE) != nat_before:
        raise AcceptanceError("Blocked traffic reached the later DNAT rule")
    lab.pass_check("blocked_traffic_does_not_reach_dnat_rule")
    lab.expect("other_source_ip_remains_allowed", True, OTHER_CLIENT)
    lab.expect("other_destination_ip_remains_allowed", True, host=OTHER_PUBLIC)
    lab.expect("other_destination_port_remains_allowed", True, port=OTHER_PORT)
    lab.expect("trusted_client_remains_allowed", True, TRUSTED_CLIENT)
    lab.expect("tcp_only_policy_does_not_block_udp", True, protocol="udp")
    firewall.sync([], mode="enforce")
    lab.expect("manual_full_state_unblock", True)
    firewall.remove(mode="enforce")
    if ("inet", config.table_name) in lab.tables() or ("ip", NAT_TABLE) not in lab.tables():
        raise AcceptanceError("Owned removal affected the wrong table")
    lab.pass_check("remove_keeps_separate_dnat_table")
    lab.expect("traffic_after_owned_table_removal", True)

    # Reconfigure only after explicitly removing the old owned scope.
    config = replace(config, protocols=("tcp", "udp"))
    firewall = lab.firewall(config)
    expiry = time.time() + 4
    firewall.sync([ProxyBan(CLIENT, expiry)], mode="enforce")
    lab.expect("explicit_tcp_udp_policy_blocks_tcp", False)
    lab.expect("explicit_tcp_udp_policy_blocks_udp", False, protocol="udp")
    lab.expect("explicit_udp_other_client_allowed", True, OTHER_CLIENT, protocol="udp")
    lab.expect("explicit_udp_trusted_client_allowed", True, TRUSTED_CLIENT, protocol="udp")
    # No adapter sync runs during this wait: expiry must come from the kernel.
    while (remaining := expiry + 0.5 - time.time()) > 0:
        time.sleep(min(0.2, remaining))
    lab.expect("kernel_ttl_restores_tcp_without_agent_refresh", True)
    lab.expect("kernel_ttl_restores_udp_without_agent_refresh", True, protocol="udp")
    firewall.remove(mode="enforce")
    if ("ip", NAT_TABLE) not in lab.tables():
        raise AcceptanceError("TTL cleanup removed the separate NAT fixture")
    lab.pass_check("ttl_cleanup_keeps_separate_dnat_table")

    # Foreign ownership must remain untouched even inside this disposable lab.
    lab.nft(f'create table inet {config.table_name} {{ comment "acceptance-foreign-owner"; }}\n')
    for operation in (lambda: firewall.sync([], mode="enforce"), lambda: firewall.remove(mode="enforce")):
        try:
            operation()
        except ProxyFirewallError:
            pass
        else:
            raise AcceptanceError("Foreign table ownership was not refused")
    table = next(row["table"] for row in lab.table_objects("inet", config.table_name) if "table" in row)
    if table.get("comment") != "acceptance-foreign-owner":
        raise AcceptanceError("Foreign table was modified")
    lab.pass_check("foreign_table_not_modified_or_removed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="store_true", help="Create and test disposable Linux namespaces as root")
    args = parser.parse_args(argv)
    if not args.run:
        parser.print_help()
        return 0
    if not sys.platform.startswith("linux") or not hasattr(os, "geteuid") or os.geteuid() != 0:
        parser.error("--run requires root on a disposable Linux test runner")
    ip_tool, nft_tool = shutil.which("ip"), shutil.which("nft")
    if not ip_tool or not nft_tool:
        parser.error("Install iproute2 and nftables on the disposable test runner")
    lab = Lab(ip_tool, nft_tool)
    original_forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text()
    original_namespace = os.readlink("/proc/self/ns/net")
    previous_handlers = {}

    def interrupted(signum, _frame):
        raise AcceptanceError(f"Acceptance interrupted by signal {signum}")

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        previous_handlers[sig] = signal.signal(sig, interrupted)
    signal.alarm(180)
    errors = []
    try:
        acceptance(lab)
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        signal.alarm(0)
        errors.extend(lab.cleanup())
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    if Path("/proc/sys/net/ipv4/ip_forward").read_text() != original_forwarding:
        errors.append("Default host forwarding state changed")
    if os.readlink("/proc/self/ns/net") != original_namespace:
        errors.append("Parent process left its original network namespace")
    summary = {"schema": "rdpguard.native-firewall-acceptance.v1", "passed": not errors,
               "checks": lab.checks, "errors": errors,
               "limitations": ["IPv4 namespace DNAT fixture; Docker/NPM and IPv6 packet paths not tested.",
                               "No Windows evidence, ActivityID, mTLS or production topology validation."]}
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
