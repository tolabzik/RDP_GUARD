"""Offline provisioning must bind identities without activating enforcement."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import subprocess

import pytest

from rdp_guard.proxy_agent import load_config


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "Bootstrap-Proxy.py"
SPEC = importlib.util.spec_from_file_location("proxy_bootstrap", SCRIPT)
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)
OPENSSL = shutil.which("openssl")


def arguments(output, **changes):
    values = dict(output=str(output), agent_host="192.0.2.10", api_bind_ip="192.0.2.10", api_port=9443,
                  computer="WIN-SERVER.example.test", stream_id="rdp-45451", backend_id="windows-1",
                  backend_ip="192.0.2.20", backend_port=45451, listener_ip="192.0.2.10", listener_port=45451,
                  relay_ip=["192.0.2.10"], admin_network=["198.51.100.7/32"],
                  nginx_log="/srv/npm/data/logs/rdpguard-stream-info.log", nginx_utc_offset_minutes=0,
                  nginx_pid_namespace=None)
    values.update(changes)
    return argparse.Namespace(**values)


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    if OPENSSL is None:
        pytest.skip("OpenSSL is needed for certificate integration tests")
    root = tmp_path_factory.mktemp("proxy-provision") / "new-bundle"
    return bootstrap.bootstrap(arguments(root))


def command(*args):
    return subprocess.run([OPENSSL, *map(str, args)], capture_output=True)


def test_bundle_binds_client_certificate_to_exact_backend_in_monitor(bundle):
    config = load_config(json.loads((bundle / "linux/config.json").read_text()))
    binding = json.loads((bundle / "windows/binding.json").read_text())
    cert = command("x509", "-in", bundle / "windows/client.pem", "-outform", "DER")
    assert cert.returncode == 0
    assert config["client_sha256"] == hashlib.sha256(cert.stdout).hexdigest()
    assert config["computer"] == binding["computer"] == "WIN-SERVER.example.test"
    assert config["stream_id"] == binding["stream_id"] == "rdp-45451"
    assert config["backend_id"] == binding["backend_id"] == "windows-1"
    assert config["enforcement_validated"] is False
    assert binding["enabled"] is True and binding["mode"] == "monitor"
    assert binding["agent_url"] == "https://192.0.2.10:9443"
    assert binding["key_file"] == r"C:\ProgramData\RDPGuard\proxy\client.key"
    assert config["whitelist"] == ["198.51.100.7/32"]
    assert json.loads((bundle / "manifest.json").read_text())["native_validation_performed"] is False


def test_ca_trust_san_and_extended_usage_are_verified(bundle):
    ca, server, client = bundle / "ca/ca.pem", bundle / "linux/server.pem", bundle / "windows/client.pem"
    assert command("verify", "-CAfile", ca, "-purpose", "sslserver", "-verify_ip", "192.0.2.10", server).returncode == 0
    assert command("verify", "-CAfile", ca, "-purpose", "sslclient", client).returncode == 0
    assert command("verify", "-CAfile", ca, "-purpose", "sslserver", client).returncode != 0
    assert command("verify", "-CAfile", ca, "-verify_ip", "192.0.2.11", server).returncode != 0
    assert command("pkey", "-in", bundle / "windows/client.key", "-pubout").stdout == command(
        "x509", "-in", client, "-pubkey", "-noout").stdout


def test_all_secret_files_and_bundle_directories_are_private(bundle):
    if os.name != "posix":
        pytest.skip("POSIX permissions")
    assert bundle.stat().st_mode & 0o777 == 0o700
    for path in bundle.rglob("*"):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
    assert (bundle / "ca/ca.key").is_file()
    assert not list((bundle / "linux").rglob("ca.key"))
    assert not list((bundle / "windows").rglob("ca.key"))
    assert not (bundle / "linux/client.key").exists()
    assert not (bundle / "windows/server.key").exists()


def test_existing_bundle_is_never_overwritten(bundle):
    before = {str(path): path.read_bytes() for path in bundle.rglob("*") if path.is_file()}
    with pytest.raises(FileExistsError):
        bootstrap.bootstrap(arguments(bundle))
    assert before == {str(path): path.read_bytes() for path in bundle.rglob("*") if path.is_file()}


@pytest.mark.parametrize("changes", [
    {"computer": "WIN/OU=injected"}, {"agent_host": "proxy.test\nDNS:other.test"},
    {"stream_id": "stream\nkey=value"}, {"admin_network": ["0.0.0.0/0"]},
    {"admin_network": ["::/0"]}, {"admin_network": []}, {"relay_ip": []},
    {"nginx_log": "relative.log"}, {"backend_port": 0}, {"listener_ip": "0.0.0.0"},
    {"listener_ip": "::"}, {"listener_ip": "127.0.0.1"}, {"backend_ip": "169.254.0.2"},
    {"admin_network": ["127.0.0.0/8"]}, {"relay_ip": ["0.0.0.0"]},
])
def test_invalid_identity_or_missing_real_whitelist_creates_nothing(tmp_path, changes):
    target = tmp_path / "absent"
    with pytest.raises(ValueError):
        bootstrap.bootstrap(arguments(target, **changes))
    assert not target.exists()


def test_host_validation_handles_ipv6_and_dns(tmp_path):
    assert bootstrap.validate(arguments(tmp_path / "unused", agent_host="2001:db8::10")).agent_san == "IP:2001:db8::10"
    assert bootstrap.validate(arguments(tmp_path / "unused", agent_host="Proxy.Example.test")).agent_san == "DNS:proxy.example.test"


def test_bootstrap_accepts_linux_log_path_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(bootstrap, "Path", PureWindowsPath)
    args = bootstrap.validate(arguments(tmp_path / "unused"))
    assert args.nginx_log == "/srv/npm/data/logs/rdpguard-stream-info.log"
    with pytest.raises(ValueError, match="absolute host path"):
        bootstrap.validate(arguments(tmp_path / "unused", nginx_log=r"C:\nginx\stream.log"))


def test_installer_shell_syntax():
    if os.name == "nt":
        pytest.skip("Linux installer shell syntax is checked on POSIX build hosts")
    shell = shutil.which("bash")
    if shell is None:
        pytest.skip("bash is required for the Linux installer syntax check")
    script = SCRIPT.with_name("Install-ProxyAgent.sh")
    result = subprocess.run([shell, "-n", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
