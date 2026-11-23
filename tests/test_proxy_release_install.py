"""Release helper must authenticate package identity before running apt or setup."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/Install-ProxyRelease.sh"
PACKAGE = "rdpguard-proxy_1.1.0-rc.2_amd64.deb"


@pytest.fixture
def installer(tmp_path):
    if os.name != "posix" or shutil.which("bash") is None:
        pytest.skip("POSIX release installer")
    import pty

    binaries = tmp_path / "bin"
    binaries.mkdir()
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    payload = downloads / PACKAGE
    payload.write_bytes(b"simulated Debian package archive\n")
    checksum = downloads / (PACKAGE + ".sha256")
    checksum.write_text(hashlib.sha256(payload.read_bytes()).hexdigest() + "  " + PACKAGE + "\n")
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    configuration = tmp_path / "config.json"
    calls = tmp_path / "calls.jsonl"
    executable = binaries / "fake-command"
    executable.write_text(f"#!{sys.executable}\n" + r'''
import hashlib, json, os, pathlib, shutil, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['COMMAND_LOG'], 'a') as log:
    log.write(json.dumps([name, *args]) + '\n')
if name == 'uname': print('Linux')
elif name == 'id': print('0')
elif name == 'dpkg':
    if args == ['--print-architecture']: print(os.environ.get('PACKAGE_ARCH', 'amd64'))
    else: sys.exit(0 if os.environ.get('INSTALLED_VERSION') == '9.0.0' else 1)
elif name == 'dpkg-query':
    if os.environ.get('INSTALLED_VERSION'): print(os.environ['INSTALLED_VERSION'], end='')
    else: sys.exit(1)
elif name == 'curl':
    if os.environ.get('DOWNLOAD_FAIL'): sys.exit(22)
    url = next(value for value in args if value.startswith('https:'))
    shutil.copyfile(pathlib.Path(os.environ['DOWNLOADS']) / url.rsplit('/', 1)[-1],
                    args[args.index('--output') + 1])
elif name == 'sha256sum':
    print(hashlib.sha256(pathlib.Path(args[0]).read_bytes()).hexdigest(), ' ', args[0])
elif name == 'dpkg-deb':
    metadata = {'Package': 'rdpguard-proxy', 'Version': '1.1.0~rc2', 'Architecture': 'amd64'}
    metadata.update(json.loads(os.environ.get('PACKAGE_METADATA', '{}')))
    print(metadata[args[-1]])
elif name == 'apt-get':
    if args[0] == 'install' and os.environ.get('INSTALL_FAIL'): sys.exit(100)
elif name == 'rdpguard-proxy':
    print('terminal=' + str(sys.stdin.isatty()))
''')
    executable.chmod(0o755)
    for name in ("uname", "id", "dpkg", "dpkg-query", "curl", "sha256sum", "dpkg-deb", "apt-get",
                 "rdpguard-proxy"):
        (binaries / name).symlink_to(executable.name)
    script = tmp_path / "installer.sh"
    script.write_text(SCRIPT.read_text().replace("/etc/os-release", str(os_release))
                      .replace("/etc/rdpguard-proxy/config.json", str(configuration))
                      .replace("/usr/bin/rdpguard-proxy", str(binaries / "rdpguard-proxy"))
                      .replace("/tmp/rdpguard-release.", str(tmp_path / "rdpguard-release.")))

    def run(*, tty=True, **options):
        environment = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ.get("PATH", ""),
                           COMMAND_LOG=str(calls), DOWNLOADS=str(downloads), **options)
        master, slave = pty.openpty() if tty else (None, None)
        try:
            result = subprocess.run([shutil.which("bash"), str(script)], env=environment,
                                    stdin=slave if tty else subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=15)
        finally:
            if tty:
                os.close(master)
                os.close(slave)
        commands = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        assert not list(tmp_path.glob("rdpguard-release.*")), "Downloaded temporary files must be removed"
        return result, commands

    return run, checksum, os_release, configuration


def mutation_calls(commands):
    return [command for command in commands if command[0] in ("apt-get", "rdpguard-proxy")]


def test_verified_release_installs_before_interactive_setup(installer):
    run, _, _, _ = installer
    result, commands = run()
    assert result.returncode == 0, result.stderr
    mutations = mutation_calls(commands)
    assert mutations[0] == ["apt-get", "update"]
    assert mutations[1][:4] == ["apt-get", "install", "-y", "--"]
    assert mutations[1][-1].endswith("/" + PACKAGE)
    assert mutations[2] == ["rdpguard-proxy", "setup"]
    assert "terminal=True" in result.stdout
    curl_calls = [command for command in commands if command[0] == "curl"]
    assert len(curl_calls) == 2
    for command in curl_calls:
        assert command[command.index("--proto") + 1] == "=https"
        assert "--fail" in command and "--tlsv1.2" in command
        url = next(value for value in command if value.startswith("https:"))
        assert url.startswith("https://github.com/tolabzik/RDP_GUARD/releases/download/v1.1.0-rc.2/")
        asset = url.rsplit("/", 1)[1]
        assert asset in (PACKAGE, PACKAGE + ".sha256")
        assert re.fullmatch(r"[A-Za-z0-9_.-]+", asset)


@pytest.mark.parametrize("change", ["wrong-hash", "wrong-file", "extra-line", "malformed", "empty"])
def test_invalid_checksum_cannot_run_apt_or_setup(installer, change):
    run, checksum, _, _ = installer
    content = checksum.read_text()
    if change == "wrong-hash":
        content = "0" * 64 + "  " + PACKAGE + "\n"
    elif change == "wrong-file":
        content = content.replace(PACKAGE, "../../other.deb")
    elif change == "extra-line":
        content += content
    elif change == "malformed":
        content = "not-a-checksum  " + PACKAGE + "\n"
    elif change == "empty":
        content = ""
    checksum.write_text(content)
    result, commands = run()
    assert result.returncode != 0
    assert mutation_calls(commands) == []


@pytest.mark.parametrize("field,value", [("Package", "different"), ("Version", "1.1.0"),
                                        ("Architecture", "arm64")])
def test_verified_bytes_with_wrong_package_metadata_cannot_install(installer, field, value):
    run, _, _, _ = installer
    result, commands = run(PACKAGE_METADATA=json.dumps({field: value}))
    assert result.returncode != 0 and "identity" in result.stderr
    assert mutation_calls(commands) == []


@pytest.mark.parametrize("kind", ["os", "architecture", "download", "noninteractive", "downgrade"])
def test_unsupported_host_download_failure_or_noninteractive_pipe_cannot_install(installer, kind):
    run, _, os_release, _ = installer
    options = {}
    if kind == "os":
        os_release.write_text('ID=debian\nVERSION_ID="12"\n')
    elif kind == "architecture":
        options["PACKAGE_ARCH"] = "arm64"
    elif kind == "download":
        options["DOWNLOAD_FAIL"] = "1"
    elif kind == "noninteractive":
        options["tty"] = False
    elif kind == "downgrade":
        options["INSTALLED_VERSION"] = "9.0.0"
    result, commands = run(**options)
    assert result.returncode != 0
    assert mutation_calls(commands) == []
    if kind != "download":
        assert not any(command[0] == "curl" for command in commands)


def test_failed_install_never_starts_setup(installer):
    run, _, _, _ = installer
    result, commands = run(INSTALL_FAIL="1")
    assert result.returncode != 0
    assert not any(command[0] == "rdpguard-proxy" for command in commands)


def test_upgrade_preserves_existing_binding_and_does_not_restart_pairing(installer):
    run, _, _, configuration = installer
    configuration.write_text('{"retained":true}')
    result, commands = run(INSTALLED_VERSION="1.1.0~dev1")
    assert result.returncode == 0, result.stderr
    assert any(command[:2] == ["apt-get", "install"] for command in commands)
    assert not any(command[0] == "rdpguard-proxy" for command in commands)
    assert configuration.read_text() == '{"retained":true}'
    assert "existing proxy configuration was retained" in result.stdout
