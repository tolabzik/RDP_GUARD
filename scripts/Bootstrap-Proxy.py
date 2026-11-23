#!/usr/bin/env python3
"""Create an offline, monitor-only proxy binding and dedicated mutual-TLS keys.

No SSH, firewall, network, service, or existing-file changes are performed.
The output directory must not exist. Keep its ca/ directory offline.
"""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys


SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
LINUX_ROOT = "/etc/rdpguard-proxy"
WINDOWS_ROOT = r"C:\ProgramData\RDPGuard\proxy"


def exclusive(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
        out.write(data.encode("utf-8") if isinstance(data, str) else data)


def write_json(path, value):
    exclusive(path, json.dumps(value, ensure_ascii=True, indent=2) + "\n")


def openssl(executable, *args):
    result = subprocess.run([executable, *map(str, args)], capture_output=True, timeout=90)
    if result.returncode:
        # Command arguments contain public identities/paths, never passwords.
        raise RuntimeError("OpenSSL failed: " + result.stderr.decode("utf-8", errors="replace")[-2000:])
    return result.stdout


def public_address(value):
    if "%" in value:
        raise ValueError("IP scope identifiers are not supported")
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local
            or str(address) == "255.255.255.255"):
        raise ValueError("Expected a concrete routable unicast address")
    return str(address)


def validate(args):
    for name in ("stream_id", "backend_id"):
        if not SLUG.fullmatch(getattr(args, name)):
            raise ValueError(f"Invalid {name}")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", args.computer):
        raise ValueError("computer must be the native Windows event Computer name")
    if "%" in args.agent_host:
        raise ValueError("Certificate IP scope identifiers are not supported")
    try:
        args.agent_host = str(ipaddress.ip_address(args.agent_host))
        args.agent_san = "IP:" + args.agent_host
    except ValueError:
        if not HOST.fullmatch(args.agent_host) or any(not DNS_LABEL.fullmatch(label)
                                                     for label in args.agent_host.split(".")):
            raise ValueError("agent-host must be a DNS name or IP address") from None
        args.agent_host = args.agent_host.lower()
        args.agent_san = "DNS:" + args.agent_host
    for name in ("api_bind_ip", "backend_ip", "listener_ip"):
        if "%" in getattr(args, name):
            raise ValueError("IP scope identifiers are not supported")
        setattr(args, name, str(ipaddress.ip_address(getattr(args, name))))
    for name in ("backend_ip", "listener_ip"):
        setattr(args, name, public_address(getattr(args, name)))
    for name in ("api_port", "backend_port", "listener_port"):
        if not 1 <= getattr(args, name) <= 65535:
            raise ValueError(f"Invalid {name}")
    if not -840 <= args.nginx_utc_offset_minutes <= 840:
        raise ValueError("Invalid nginx UTC offset")
    if not PurePosixPath(args.nginx_log).is_absolute():
        raise ValueError("nginx-log must be an absolute host path")
    args.relay_ip = sorted({public_address(value) for value in args.relay_ip})
    args.admin_network = sorted({str(ipaddress.ip_network(value, strict=True)) for value in args.admin_network})
    for value in args.admin_network:
        network = ipaddress.ip_network(value)
        protected = (["0.0.0.0/32", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"]
                     if network.version == 4 else ["::/128", "::1/128", "ff00::/8", "::ffff:0:0/96"])
        if network.prefixlen == 0 or any(network.overlaps(ipaddress.ip_network(item)) for item in protected):
            raise ValueError("Administrator network includes protected or all-address ranges")
    if not 1 <= len(args.relay_ip) <= 16 or not 1 <= len(args.admin_network) <= 1000:
        raise ValueError("At least one relay IP and administrator network are required")
    return args


def bootstrap(args):
    args = validate(args)
    executable = shutil.which("openssl")
    if executable is None:
        raise RuntimeError("OpenSSL is required locally")
    root = Path(args.output).absolute()
    previous_umask = os.umask(0o077)
    try:
        root.mkdir(mode=0o700)  # Exclusive: never merge or replace an existing bundle.
        for name in ("ca", "linux", "windows"):
            (root / name).mkdir(mode=0o700)
        ca, linux, windows = (root / name for name in ("ca", "linux", "windows"))
        ca_conf = ca / "ca.cnf"
        exclusive(ca_conf, "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n"
                  f"[dn]\nCN=RDPGuard-{args.stream_id}-CA\n"
                  "[ca]\nbasicConstraints=critical,CA:true,pathlen:0\n"
                  "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
        openssl(executable, "req", "-new", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256",
                "-days", "3650", "-config", ca_conf, "-keyout", ca / "ca.key", "-out", ca / "ca.pem")
        for name, target, purpose, subject, san in (
            ("server", linux, "serverAuth", args.agent_host, args.agent_san),
            ("client", windows, "clientAuth", args.computer, None),
        ):
            key, cert, csr, extension = (target / (name + suffix) for suffix in (".key", ".pem", ".csr", ".ext"))
            exclusive(extension, "basicConstraints=critical,CA:false\n"
                      "keyUsage=critical,digitalSignature,keyEncipherment\n"
                      f"extendedKeyUsage={purpose}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
                      + (f"subjectAltName={san}\n" if san else ""))
            openssl(executable, "req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256",
                    "-subj", "/CN=" + subject, "-keyout", key, "-out", csr)
            openssl(executable, "x509", "-req", "-in", csr, "-CA", ca / "ca.pem", "-CAkey", ca / "ca.key",
                    "-set_serial", "0x" + os.urandom(16).hex(), "-days", "365", "-sha256",
                    "-extfile", extension, "-out", cert)
            openssl(executable, "verify", "-CAfile", ca / "ca.pem", "-purpose",
                    "sslserver" if name == "server" else "sslclient", cert)
            exclusive(target / "ca.pem", (ca / "ca.pem").read_bytes())
            csr.unlink()
            extension.unlink()
        fingerprint = hashlib.sha256(openssl(executable, "x509", "-in", windows / "client.pem",
                                             "-outform", "DER")).hexdigest()
        config = {
            "schema": "rdpguard.proxy-agent.v1", "stream_id": args.stream_id, "backend_id": args.backend_id,
            "computer": args.computer, "client_sha256": fingerprint,
            "api_host": args.api_bind_ip, "api_port": args.api_port,
            "ca_file": LINUX_ROOT + "/ca.pem", "cert_file": LINUX_ROOT + "/server.pem",
            "key_file": LINUX_ROOT + "/server.key", "nginx_log": args.nginx_log,
            "backend_ip": args.backend_ip, "backend_port": args.backend_port,
            "listener_ip": args.listener_ip, "listener_port": args.listener_port,
            "relay_ips": args.relay_ip, "nginx_utc_offset_minutes": args.nginx_utc_offset_minutes,
            "nginx_pid_namespace": args.nginx_pid_namespace, "whitelist": args.admin_network,
            "state_file": "/var/lib/rdpguard-proxy/state.sqlite3", "enforcement_validated": False,
            "protocols": ["tcp"], "epoch_seconds": 900, "max_records": 100000,
            "max_log_bytes": 64 * 1024 * 1024,
        }
        host = "[" + args.agent_host + "]" if ":" in args.agent_host else args.agent_host
        binding = {
            "enabled": True, "mode": "monitor", "agent_url": f"https://{host}:{args.api_port}",
            "stream_id": args.stream_id, "backend_id": args.backend_id, "computer": args.computer,
            "ca_file": WINDOWS_ROOT + r"\ca.pem", "cert_file": WINDOWS_ROOT + r"\client.pem",
            "key_file": WINDOWS_ROOT + r"\client.key", "relay_ips": args.relay_ip,
        }
        write_json(linux / "config.json", config)
        write_json(windows / "binding.json", binding)
        write_json(root / "manifest.json", {"schema": "rdpguard.proxy-bootstrap.v1", "mode": "monitor",
                   "stream_id": args.stream_id, "backend_id": args.backend_id, "computer": args.computer,
                   "client_sha256": fingerprint, "agent_url": binding["agent_url"],
                   "native_validation_performed": False, "ca_private_key": "ca/ca.key"})
        for path in root.rglob("*"):
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
        return root
    finally:
        os.umask(previous_umask)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="New local directory; must not exist")
    parser.add_argument("--agent-host", required=True, help="Agent HTTPS certificate DNS name or IP")
    parser.add_argument("--api-bind-ip", default="127.0.0.1", help="Explicit Linux API bind IP")
    parser.add_argument("--api-port", type=int, default=9443)
    parser.add_argument("--computer", required=True, help="Exact native Windows event Computer value")
    parser.add_argument("--stream-id", required=True)
    parser.add_argument("--backend-id", required=True)
    parser.add_argument("--backend-ip", required=True)
    parser.add_argument("--backend-port", required=True, type=int)
    parser.add_argument("--listener-ip", required=True, help="Concrete public destination IP of the RDP listener")
    parser.add_argument("--listener-port", required=True, type=int)
    parser.add_argument("--relay-ip", action="append", required=True)
    parser.add_argument("--admin-network", action="append", required=True,
                        help="Real administrator source IP/CIDR; repeat as needed")
    parser.add_argument("--nginx-log", required=True, help="Absolute nginx INFO-log path on Linux host")
    parser.add_argument("--nginx-utc-offset-minutes", required=True, type=int)
    parser.add_argument("--nginx-pid-namespace", default=None)
    args = parser.parse_args(argv)
    try:
        output = bootstrap(args)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"Bootstrap failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"output": str(output), "mode": "monitor", "installed": False,
                      "native_validation_performed": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
