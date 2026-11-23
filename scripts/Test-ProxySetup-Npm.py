#!/usr/bin/env python3
"""Opt-in setup acceptance with a disposable NPM container, never a working proxy.

Requires a disposable Linux CI host with root, Docker, iproute2 and the pulled
image. Creates one uniquely named dummy interface and container, and removes
only those resources in finally. No production endpoint is contacted.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


ADDRESS = "192.0.2.45"
LISTENER = 45451
BACKEND = 45452


def command(args, *, timeout=15, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Command failed: {args[:5]}: {result.stderr[-2000:]}")
    return result.stdout


def wait_ready(probe, seconds=90):
    until, last = time.monotonic() + seconds, None
    while time.monotonic() < until:
        try:
            return probe()
        except Exception as exc:
            last = exc
            time.sleep(1)
    raise RuntimeError("Disposable NPM did not become ready") from last


def probe():
    with socket.create_connection((ADDRESS, LISTENER), timeout=3) as connection:
        payload = b"rdpguard-npm-setup-acceptance"
        connection.sendall(payload)
        if connection.recv(4096) != payload:
            raise RuntimeError("NPM fixture did not forward the test connection")


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        self.request.sendall(self.request.recv(4096))


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--image", default="jc21/nginx-proxy-manager:2.17.1")
    args = parser.parse_args(argv)
    if not args.run:
        parser.print_help()
        return 0
    if sys.platform != "linux" or os.geteuid() != 0 or not shutil.which("docker") or not shutil.which("ip"):
        parser.error("Use root on a disposable Linux CI host with Docker and iproute2")
    from rdp_guard.proxy_setup import apply_info_logging, discover_streams, install_enrollment
    from rdp_guard.proxy_pairing import create_pairing

    # Refuse pre-existing topology instead of borrowing an interface or port.
    addresses = json.loads(command(["ip", "-j", "address", "show"]))
    if any(a.get("local") == ADDRESS for row in addresses for a in row.get("addr_info", [])):
        raise RuntimeError("Acceptance address already exists; refusing to use it")
    suffix = uuid.uuid4().hex[:10]
    interface, container = "rgp" + suffix, "rdpguard-setup-" + suffix
    owned_interface = owned_container = False
    server = None
    checks, errors, image_id = [], [], ""

    def passed(name):
        checks.append(name)
        print(json.dumps({"check": name, "status": "passed"}), flush=True)

    with tempfile.TemporaryDirectory(prefix="rdpguard-npm-acceptance-") as directory:
        root = Path(directory)
        try:
            command(["ip", "link", "add", interface, "type", "dummy"])
            owned_interface = True
            command(["ip", "addr", "add", ADDRESS + "/32", "dev", interface])
            command(["ip", "link", "set", interface, "up"])
            server = EchoServer((ADDRESS, BACKEND), Echo)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            data, certificates = root / "data", root / "letsencrypt"
            data.mkdir(mode=0o755)
            certificates.mkdir(mode=0o755)
            image_id = command(["docker", "image", "inspect", args.image, "--format", "{{.Id}}"]).strip()
            command(["docker", "create", "--name", container,
                     "--label", "rdpguard.acceptance=" + suffix,
                     "-e", "DISABLE_IPV6=true", "-e", "IP_RANGES_FETCH_ENABLED=false", "-e", "TZ=UTC",
                     "-p", f"{ADDRESS}:{LISTENER}:{LISTENER}/tcp",
                     "--mount", f"type=bind,source={data},target=/data",
                     "--mount", f"type=bind,source={certificates},target=/etc/letsencrypt", args.image], timeout=30)
            owned_container = True
            command(["docker", "start", container], timeout=30)

            def initialized():
                if not (data / "nginx" / "stream").is_dir():
                    raise RuntimeError("NPM data layout not ready")
                command(["docker", "exec", container, "nginx", "-t"])

            wait_ready(initialized)
            passed("official_npm_image_starts")
            stream_path = data / "nginx" / "stream" / "987654.conf"
            # This is a test-owned synthetic stream in a fresh container only.
            # Setup itself is not allowed to edit generated stream files.
            stream_text = f"""# RDP Guard disposable acceptance stream
server {{
  listen {LISTENER} reuseport;
  proxy_pass {ADDRESS}:{BACKEND};
  access_log /data/logs/stream-987654_access.log stream;
  error_log /data/logs/stream-987654_error.log warn;
  include /data/nginx/custom/server_stream[.]conf;
  include /data/nginx/custom/server_stream_tcp[.]conf;
}}
"""
            stream_path.write_text(stream_text)
            include = data / "nginx" / "custom" / "server_stream_tcp.conf"
            include.parent.mkdir(exist_ok=True)
            original = b"# existing operator configuration must survive setup\n"
            include.write_bytes(original)
            command(["docker", "exec", container, "nginx", "-t"])
            command(["docker", "exec", container, "nginx", "-s", "reload"])
            wait_ready(probe, 15)
            passed("tcp_stream_forwards_before_setup")

            streams = discover_streams(runner=command)
            selected = [s for s in streams if s.container_name.lstrip("/") == container
                        and s.container_port == LISTENER and s.backend_port == BACKEND]
            if len(selected) != 1:
                raise RuntimeError("Setup did not uniquely discover the test stream")
            stream = selected[0]
            if (stream.backend_ip != ADDRESS or stream.data_path != data
                    or (ADDRESS, LISTENER) not in stream.bindings):
                raise RuntimeError("Docker port/mount/backend discovery differs from fixture")
            passed("setup_discovers_real_docker_stream_and_mount")
            change = apply_info_logging(stream, root / "backup", runner=command)
            if not include.read_bytes().startswith(original):
                raise RuntimeError("Setup lost existing custom include content")
            if stream_path.read_text() != stream_text:
                raise RuntimeError("Setup modified the generated stream configuration")
            passed("setup_preserves_custom_and_generated_configuration")
            wait_ready(probe, 15)
            log = data / "logs" / "rdpguard-stream-info.log"

            def logged():
                if not log.is_file() or "client" not in log.read_text(errors="replace"):
                    raise RuntimeError("NPM INFO connection evidence not written")

            wait_ready(logged, 10)
            passed("native_nginx_info_log_records_connection")
            # Exercise the actual setup-generated rotation rule, with only the
            # disposable NPM log and certificate/config directory in scope.
            pairing_directory = root / "pairing"
            plan = dict(agent_url=f"https://{ADDRESS}:9443", api_port=9443,
                        stream_id="npm-test", backend_id="echo-test", listener_ip=ADDRESS,
                        relay_ips=[ADDRESS], whitelist=["198.51.100.7/32"])
            settings = {key: value for key, value in plan.items() if key != "api_port"}
            settings.update(listener_port=LISTENER, backend_ip=ADDRESS,
                            backend_port=BACKEND, protocols=["tcp"])
            create_pairing(pairing_directory, settings)
            installed = root / "installed-config"
            install_enrollment(dict(computer="TEST-WINDOWS", client_sha256="a" * 64),
                               stream, plan, pairing_directory, destination=installed)
            command(["logrotate", "--force", "--state", str(root / "rotation.state"),
                     str(installed / "logrotate.conf")])
            if not log.with_name(log.name + ".1").is_file():
                raise RuntimeError("Rotation did not preserve the old evidence log")

            def reopened():
                if not log.is_file():
                    raise RuntimeError("NPM has not reopened the rotated log")

            wait_ready(reopened, 10)
            wait_ready(probe, 15)
            wait_ready(logged, 10)
            passed("generated_logrotate_reopens_only_owned_npm_log")
            change.rollback()
            if include.read_bytes() != original or stream_path.read_text() != stream_text:
                raise RuntimeError("Rollback did not restore original bytes")
            wait_ready(probe, 15)
            passed("rollback_restores_configuration_and_forwarding")
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if owned_container:
                try:
                    label = command(["docker", "inspect", container, "--format",
                                     '{{index .Config.Labels "rdpguard.acceptance"}}']).strip()
                    if label != suffix:
                        raise RuntimeError("Container ownership changed; refusing removal")
                    command(["docker", "rm", "-f", container], timeout=30)
                except Exception as exc:
                    errors.append("Container cleanup: " + str(exc))
            if owned_interface:
                try:
                    command(["ip", "link", "delete", interface])
                except Exception as exc:
                    errors.append("Interface cleanup: " + str(exc))
    report = {"schema": "rdpguard.npm-setup-acceptance.v1", "passed": not errors,
              "image": args.image, "image_id": image_id, "checks": checks, "errors": errors,
              "limitations": ["Synthetic TCP echo backend, not Windows/RDP.",
                              "No automatic ban or target production topology acceptance."]}
    output = Path("test-results")
    output.mkdir(exist_ok=True)
    (output / "npm-setup.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
