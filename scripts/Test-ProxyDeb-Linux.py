#!/usr/bin/env python3
"""Opt-in package smoke test for a disposable Ubuntu 24.04 systemd CI runner.

Installs a local .deb, exercises stopped/running upgrades and remove/purge, and
verifies preservation of a test binding. Refuses any existing agent/config/data.
No production endpoint is contacted; the temporary API binds loopback only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
CONFIG = Path('/etc/rdpguard-proxy')
STATE = Path('/var/lib/rdpguard-proxy')
CHECKS = []


def run(args, check=True):
    return subprocess.run(list(map(str, args)), text=True, capture_output=True, check=check,
                          timeout=300, env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'))


def active(unit='rdpguard-proxy.service'):
    return run(['systemctl', 'is-active', '--quiet', unit], False).returncode == 0


def enabled(unit='rdpguard-proxy.service'):
    return run(['systemctl', 'is-enabled', '--quiet', unit], False).returncode == 0


def config_hashes():
    return {str(path.relative_to(CONFIG)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in CONFIG.rglob('*') if path.is_file()}


def expect(value, message):
    if not value:
        raise RuntimeError(message)
    print(json.dumps({'check': message, 'passed': True}), flush=True)
    CHECKS.append(message)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--deb', type=Path)
    args = parser.parse_args(argv)
    if not args.run:
        parser.print_help()
        return 0
    if sys.platform != 'linux' or os.geteuid() != 0 or not Path('/run/systemd/system').exists():
        parser.error('Disposable Linux root/systemd runner required')
    if args.deb is None or not args.deb.is_file():
        parser.error('Provide the built local .deb')
    for path in (CONFIG, STATE, Path('/opt/rdpguard-proxy'), Path('/usr/bin/rdpguard-proxy')):
        if path.exists() or path.is_symlink():
            parser.error('Refusing existing customer installation: ' + str(path))
    artifact = args.deb.resolve()
    owned, errors = False, []
    CHECKS.clear()
    try:
        with tempfile.TemporaryDirectory(prefix='rdpg-deb-smoke-') as temporary:
            root = Path(temporary)
            run(['apt-get', 'install', '-y', str(artifact)])
            expect(not active() and not enabled(), 'fresh_install_does_not_start_or_enable_agent')
            expect(not CONFIG.exists(), 'fresh_install_does_not_generate_configuration_or_keys')
            run(['/usr/bin/rdpguard-proxy', '--help'])
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                api_port = sock.getsockname()[1]
            run([sys.executable, ROOT / 'scripts/Bootstrap-Proxy.py', '--output', root / 'bundle',
                 '--agent-host', '127.0.0.1', '--api-bind-ip', '127.0.0.1', '--api-port', api_port,
                 '--computer', 'PACKAGE-SMOKE', '--stream-id', 'smoke', '--backend-id', 'windows',
                 '--backend-ip', '192.0.2.20', '--backend-port', '45451', '--listener-ip', '192.0.2.10',
                 '--listener-port', '45451', '--relay-ip', '192.0.2.10', '--admin-network', '198.51.100.7/32',
                 '--nginx-log', STATE / 'smoke-info.log', '--nginx-utc-offset-minutes', '0'])
            shutil.copytree(root / 'bundle/linux', CONFIG)
            STATE.mkdir(mode=0o700)
            owned = True
            (STATE / 'smoke-info.log').write_text('')
            (STATE / 'customer-sentinel').write_text('preserve this state')
            # Three independent scopes: legacy and named running, another named stopped.
            # Test-only loopback certs can be reused here; setup tests check separate issuance.
            used_ports = {api_port}
            for name, listener_port in [('second', 45452), ('standby', 45453)]:
                folder, state = CONFIG / 'instances' / name, STATE / 'instances' / name
                shutil.copytree(root / 'bundle/linux', folder)
                state.mkdir(parents=True, mode=0o700)
                config = json.loads((folder / 'config.json').read_text())
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
                if port in used_ports:
                    raise RuntimeError('CI ephemeral API ports collided')
                used_ports.add(port)
                config.update(api_port=port, stream_id=name, backend_id=name,
                              listener_port=listener_port, backend_port=listener_port,
                              state_file=str(state / 'state.sqlite3'))
                for key, filename in [('ca_file', 'ca.pem'), ('cert_file', 'server.pem'), ('key_file', 'server.key')]:
                    config[key] = str(folder / filename)
                (folder / 'config.json').write_text(json.dumps(config))
            before = config_hashes()
            run(['/usr/bin/rdpguard-proxy', '--config', CONFIG / 'config.json', '--check-config'])
            run(['dpkg', '-i', artifact])
            expect(not active() and not enabled(), 'stopped_disabled_upgrade_remains_stopped_disabled')
            run(['systemctl', 'enable', 'rdpguard-proxy.service'])
            run(['systemctl', 'start', 'rdpguard-proxy.service'])
            run(['systemctl', 'start', 'rdpguard-proxy@second.service'])
            run(['systemctl', 'enable', 'rdpguard-proxy@standby.service'])
            time.sleep(2)
            expect(active(), 'packaged_entrypoint_runs_from_private_libraries')
            expect(active('rdpguard-proxy@second.service'), 'named_unit_starts_with_own_config_and_database')
            run(['dpkg', '-i', artifact])
            time.sleep(2)
            expect(active() and enabled(), 'running_enabled_upgrade_restores_only_previous_running_state')
            expect(active('rdpguard-proxy@second.service') and not enabled('rdpguard-proxy@second.service'),
                   'running_disabled_named_unit_restarts_without_enabling')
            expect(not active('rdpguard-proxy@standby.service') and enabled('rdpguard-proxy@standby.service'),
                   'stopped_enabled_named_unit_is_not_started_by_upgrade')
            expect((STATE / 'instances/second/state.sqlite3').is_file(), 'named_unit_uses_separate_database')
            after = config_hashes()
            expect(before == after, 'upgrade_preserves_config_certificates_and_keys')
            expect((STATE / 'customer-sentinel').read_text() == 'preserve this state', 'upgrade_preserves_customer_state')
            run(['systemctl', 'stop', 'rdpguard-proxy.service'])
            run(['dpkg', '-i', artifact])
            expect(not active() and enabled(), 'stopped_enabled_upgrade_does_not_start_service')
            expect(active('rdpguard-proxy@second.service'), 'legacy_stop_does_not_stop_named_unit')
            run(['apt-get', 'remove', '-y', 'rdpguard-proxy'])
            expect(not active() and CONFIG.is_dir() and (STATE / 'customer-sentinel').exists(), 'remove_stops_agent_preserves_customer_data')
            expect(not active('rdpguard-proxy@second.service') and not enabled('rdpguard-proxy@standby.service'),
                   'remove_stops_and_disables_named_units')
            expect(before == config_hashes(), 'remove_preserves_all_instance_credentials')
            run(['apt-get', 'purge', '-y', 'rdpguard-proxy'])
            expect(CONFIG.is_dir() and (STATE / 'customer-sentinel').exists(), 'purge_preserves_customer_keys_and_state')
    except Exception as exc:
        errors.append(f'{type(exc).__name__}: {exc}')
        if isinstance(exc, subprocess.CalledProcessError):
            errors.append((exc.stdout or '')[-4000:] + (exc.stderr or '')[-4000:])
    finally:
        run(['systemctl', 'stop', 'rdpguard-proxy.service', 'rdpguard-proxy@second.service',
             'rdpguard-proxy@standby.service', 'rdpguard-proxy-logrotate.timer'], False)
        run(['apt-get', 'purge', '-y', 'rdpguard-proxy'], False)
        if owned:
            shutil.rmtree(CONFIG)
            shutil.rmtree(STATE)
        report = {'schema': 'rdpguard.deb-package-acceptance.v1', 'passed': not errors,
                  'artifact': artifact.name, 'checks': CHECKS, 'errors': errors,
                  'limitations': ['Disposable Ubuntu package lifecycle; no production deployment.',
                                  'Monitor API startup only; no Windows/RDP enforcement acceptance.']}
        output = ROOT / 'test-results'
        output.mkdir(exist_ok=True)
        (output / 'deb-package.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report), flush=True)
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
