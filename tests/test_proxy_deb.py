"""Portable staging and lifecycle contracts for the explicitly configured package."""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_proxy_deb", ROOT / "scripts/Build-ProxyDeb.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def application_wheel(tmp_path, version="1.1.0.dev1", name="rdp-guard", *, duplicate=False):
    path = tmp_path / "rdp_guard-test-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nRequires-Dist: cryptography>=44\n\n"
        archive.writestr("rdp_guard-1.dist-info/METADATA", metadata)
        archive.writestr("rdp_guard-1.dist-info/WHEEL", "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr("rdp_guard/__init__.py", f"__version__ = {version!r}\n")
        if duplicate:
            archive.writestr("other-1.dist-info/METADATA", metadata)
    return path


def fake_pip(calls):
    def run(arguments, *, check):
        assert check is True
        calls.append(arguments)
        target = Path(arguments[arguments.index("--target") + 1])
        for package in ("rdp_guard", "cryptography"):
            (target / package).mkdir()
            (target / package / "__init__.py").write_text("# fixture installed by fake pip\n")
        (target / "bin").mkdir()
        (target / "bin/rdpguard").write_text("duplicate wheel entry point")
        return subprocess.CompletedProcess(arguments, 0)
    return run


@pytest.mark.parametrize("offline", [False, True])
def test_staging_installs_dependencies_only_into_private_library(tmp_path, offline):
    wheel = application_wheel(tmp_path)
    stage, calls = tmp_path / "stage", []
    wheelhouse = tmp_path / "wheelhouse" if offline else None
    version = builder.stage_package(stage, wheel, runner=fake_pip(calls), wheelhouse=wheelhouse)
    assert version == "1.1.0~dev1"
    assert len(calls) == 1
    command = calls[0]
    assert command[:4] == [sys.executable, "-m", "pip", "--isolated"]
    assert "install" in command and "--no-deps" not in command
    assert "--only-binary=:all:" in command and "--no-compile" in command
    assert ("--no-index" in command) is offline
    assert ("--find-links" in command) is offline
    if offline:
        assert command[command.index("--find-links") + 1] == str(wheelhouse)
    library = stage / "usr/lib/rdpguard-proxy"
    assert command[command.index("--target") + 1] == str(library)
    assert command[-1] == str(wheel)
    assert (library / "rdp_guard/__init__.py").is_file()
    assert (library / "cryptography/__init__.py").is_file()
    assert not (library / "bin").exists()
    assert not (stage / "usr/local").exists()
    assert not list(stage.rglob("site-packages"))


@pytest.mark.parametrize("version,expected", [
    ("1.1.0.dev1", "1.1.0~dev1"), ("1.1.0rc2", "1.1.0~rc2"), ("1.1.0", "1.1.0"),
])
def test_wheel_version_preserves_debian_prerelease_ordering(tmp_path, version, expected):
    assert builder.wheel_version(application_wheel(tmp_path, version)) == expected


@pytest.mark.parametrize("source,expected", [
    ("1.1.0.dev1", "rdpguard-proxy_1.1.0-dev.1_amd64.deb"),
    ("1.1.0rc2", "rdpguard-proxy_1.1.0-rc.2_amd64.deb"),
    ("1.1.0", "rdpguard-proxy_1.1.0_amd64.deb"),
])
def test_download_name_survives_release_upload_without_changing_debian_version(tmp_path, source, expected):
    version = builder.wheel_version(application_wheel(tmp_path, source))
    assert builder.package_filename(version) == expected
    assert re.fullmatch(r"[A-Za-z0-9_.-]+", expected)
    if source != "1.1.0":
        assert "~" in version  # Debian ordering remains separate from the asset name.


@pytest.mark.parametrize("options", [
    {"name": "another-application"}, {"version": "1.1.0+unreviewed"},
    {"version": "1.1.0;unexpected"}, {"duplicate": True},
])
def test_unexpected_wheel_identity_or_metadata_cannot_be_packaged(tmp_path, options):
    wheel = application_wheel(tmp_path, **options)
    stage, calls = tmp_path / "stage", []
    with pytest.raises(ValueError):
        builder.stage_package(stage, wheel, runner=fake_pip(calls))
    assert calls == [] and not stage.exists()


def test_dependency_install_failure_never_creates_a_finished_package_control(tmp_path):
    wheel = application_wheel(tmp_path)
    stage = tmp_path / "stage"

    def failed_pip(command, *, check):
        raise subprocess.CalledProcessError(1, command)

    with pytest.raises(subprocess.CalledProcessError):
        builder.stage_package(stage, wheel, runner=failed_pip)
    assert not (stage / "DEBIAN/control").exists()
    assert not (stage / "usr/bin/rdpguard-proxy").exists()


def test_staged_control_entrypoint_and_units_keep_private_runtime_contract(tmp_path, monkeypatch):
    wheel = application_wheel(tmp_path)
    stage, calls, modes = tmp_path / "stage", [], []
    real_chmod = os.chmod

    def recorded_chmod(path, mode, *args, **kwargs):
        modes.append((Path(path), mode))
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(builder.os, "chmod", recorded_chmod)
    builder.stage_package(stage, wheel, runner=fake_pip(calls))
    control = (stage / "DEBIAN/control").read_text()
    fields = dict(line.split(": ", 1) for line in control.splitlines() if line and not line.startswith(" "))
    assert fields["Package"] == "rdpguard-proxy" and fields["Architecture"] == "amd64"
    assert {"python3.12", "nftables", "iproute2", "openssl", "ca-certificates", "systemd", "logrotate"} <= {
        item.strip() for item in fields["Depends"].split(",")}
    assert "pip" not in fields["Depends"]  # Deployment does not download Python dependencies.
    launcher = stage / "usr/bin/rdpguard-proxy"
    source = launcher.read_text()
    assert source.splitlines()[0] == "#!/usr/bin/python3.12 -I"
    assert "sys.path.insert(0, '/usr/lib/rdpguard-proxy')" in source
    compile(source, str(launcher), "exec")
    expected = {"preinst", "postinst", "prerm", "postrm"}
    assert {(path.name, mode) for path, mode in modes if path.parent == stage / "DEBIAN"} == {
        *((name, 0o755) for name in expected), ("control", 0o644)}
    if os.name == "posix":
        assert stat.S_IMODE(launcher.stat().st_mode) == 0o755
        for name in expected:
            assert stat.S_IMODE((stage / "DEBIAN" / name).stat().st_mode) == 0o755
    service = (stage / "usr/lib/systemd/system/rdpguard-proxy.service").read_text()
    assert "ConditionPathExists=/etc/rdpguard-proxy/config.json" in service
    assert "ExecStart=/usr/bin/rdpguard-proxy --config /etc/rdpguard-proxy/config.json" in service
    assert "UMask=0077" in service and "StateDirectoryMode=0700" in service
    assert "ProtectSystem=strict" in service and "ReadWritePaths=/var/lib/rdpguard-proxy" in service
    assert (stage / "usr/share/doc/rdpguard-proxy/PROXY_SETUP.md").is_file()


@pytest.fixture
def maintainer(tmp_path):
    if os.name != "posix" or shutil.which("sh") is None:
        pytest.skip("POSIX shell lifecycle checks")
    sandbox, binaries = tmp_path / "root", tmp_path / "bin"
    sandbox.mkdir()
    (sandbox / 'run').mkdir()
    binaries.mkdir()
    log = tmp_path / "systemctl.calls"
    fake = binaries / "systemctl"
    fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMMAND_LOG"\n'
                    'if [ "$1" = is-active ]; then\n'
                    ' if [ -n "$ACTIVE_UNITS" ]; then case ",$ACTIVE_UNITS," in *",$3,"*) exit 0;; *) exit 1;; esac; fi\n'
                    ' exit "${SERVICE_ACTIVE:-1}"; fi\nexit 0\n')
    fake.chmod(0o755)

    def run(name, action, *, active=False, active_units=''):
        source = (ROOT / "deploy/debian/DEBIAN" / name).read_text()
        # Every package-owned absolute location is redirected into this fixture.
        source = re.sub(r"/(?:run|etc|opt|var)/", lambda match: str(sandbox) + match[0], source)
        source = source.replace("/usr/bin/python3.12", '"' + sys.executable + '"')
        path = tmp_path / name
        path.write_text(source)
        environment = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ.get("PATH", ""),
                           COMMAND_LOG=str(log), SERVICE_ACTIVE="0" if active else "1", ACTIVE_UNITS=active_units)
        result = subprocess.run([shutil.which("sh"), str(path), action], env=environment,
                                capture_output=True, text=True, timeout=10)
        commands = log.read_text().splitlines() if log.exists() else []
        return result, commands

    return sandbox, run


def test_new_install_neither_starts_nor_enables_service(maintainer):
    sandbox, run = maintainer
    result, commands = run("postinst", "configure")
    assert result.returncode == 0, result.stderr
    assert commands == ["daemon-reload"]
    assert not (sandbox / "etc/rdpguard-proxy/config.json").exists()


@pytest.mark.parametrize("active", [False, True])
def test_upgrade_restarts_only_previously_running_agent_and_discards_stale_marker(maintainer, active):
    sandbox, run = maintainer
    marker = sandbox / "run/rdpguard-proxy-package/was-running"
    marker.parent.mkdir(parents=True)
    marker.write_text("old marker")
    config = sandbox / "etc/rdpguard-proxy/config.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"mode":"monitor"}')
    result, commands = run("prerm", "upgrade", active=active)
    assert result.returncode == 0, result.stderr
    assert marker.exists() is active
    assert ("stop rdpguard-proxy.service" in commands) is active
    result, commands = run("postinst", "configure", active=active)
    assert result.returncode == 0, result.stderr
    assert ("start rdpguard-proxy.service" in commands) is active
    assert not any(command.startswith("enable ") for command in commands)
    assert not marker.exists() and config.read_text() == '{"mode":"monitor"}'


@pytest.mark.parametrize("logging_active", [False, True])
def test_removal_refuses_managed_logging_and_preserves_customer_state(maintainer, logging_active):
    sandbox, run = maintainer
    state = sandbox / "var/lib/rdpguard-proxy/setup-state.json"
    state.parent.mkdir(parents=True)
    state.write_text('{"logging_active":' + str(logging_active).lower() + '}')
    certificate = sandbox / "etc/rdpguard-proxy/client.pem"
    certificate.parent.mkdir(parents=True)
    certificate.write_text("customer certificate")
    original = state.read_text()
    result, commands = run("prerm", "remove")
    assert (result.returncode != 0) is logging_active
    assert any(command.startswith("stop ") for command in commands) is not logging_active
    assert any(command.startswith("disable ") for command in commands) is not logging_active
    assert state.read_text() == original and certificate.read_text() == "customer certificate"
    if logging_active:
        assert "unconfigure" in result.stderr
    else:
        result, commands = run("postrm", "purge")
        assert result.returncode == 0, result.stderr
        assert "preserved" in result.stdout
        assert state.read_text() == original and certificate.read_text() == "customer certificate"


@pytest.mark.parametrize("manual_path", ["opt/rdpguard-proxy", "etc/systemd/system/rdpguard-proxy.service"])
def test_install_refuses_to_overwrite_manual_deployment(maintainer, manual_path):
    sandbox, run = maintainer
    previous = sandbox / manual_path
    previous.parent.mkdir(parents=True)
    previous.write_text("existing administrator-managed installation")
    result, commands = run("preinst", "install")
    assert result.returncode != 0 and "Migrate it explicitly" in result.stderr
    assert previous.read_text() == "existing administrator-managed installation"
    assert commands == []


def test_upgrade_with_missing_configuration_keeps_recovery_marker_and_does_not_start(maintainer):
    sandbox, run = maintainer
    marker = sandbox / "run/rdpguard-proxy-package/was-running"
    marker.parent.mkdir(parents=True)
    marker.write_text("")
    result, commands = run("postinst", "configure")
    assert result.returncode != 0 and "refusing restart" in result.stderr
    assert marker.exists()
    assert commands == ["daemon-reload"]


def test_upgrade_restores_only_the_running_named_instances(maintainer):
    sandbox, run = maintainer
    for name in ('accounting', 'standby'):
        path = sandbox / 'etc/rdpguard-proxy/instances' / name / 'config.json'
        path.parent.mkdir(parents=True)
        path.write_text('{"customer":"unchanged"}')
    result, commands = run('prerm', 'upgrade', active_units='rdpguard-proxy@accounting.service')
    assert result.returncode == 0, result.stderr
    assert 'stop rdpguard-proxy@accounting.service' in commands
    assert 'stop rdpguard-proxy@standby.service' not in commands
    result, commands = run('postinst', 'configure')
    assert result.returncode == 0, result.stderr
    assert 'start rdpguard-proxy@accounting.service' in commands
    assert 'start rdpguard-proxy@standby.service' not in commands
    assert 'start rdpguard-proxy.service' not in commands
    assert not any(command.startswith('enable ') for command in commands)
    assert not list((sandbox / 'run/rdpguard-proxy-package').iterdir())


def test_removal_requires_detaching_named_logging_even_without_legacy_state(maintainer):
    sandbox, run = maintainer
    state = sandbox / 'var/lib/rdpguard-proxy/instances/accounting/setup-state.json'
    state.parent.mkdir(parents=True)
    state.write_text('{"logging_active":true}')
    result, commands = run('prerm', 'remove')
    assert result.returncode != 0 and '--instance NAME' in result.stderr
    assert commands == []


def test_package_upgrade_refuses_while_pairing_without_stopping_nodes(maintainer):
    import fcntl
    sandbox, run = maintainer
    with (sandbox / 'run/rdpguard-proxy-management.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result, commands = run('prerm', 'upgrade', active=True)
    assert result.returncode != 0 and 'setup is running' in result.stderr
    assert commands == []
