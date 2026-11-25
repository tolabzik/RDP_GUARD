"""Setup discovery and nginx edits must be scoped, conservative and reversible."""
import json
import os
from types import SimpleNamespace

import pytest

from rdp_guard import proxy_setup as setup


pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Linux setup uses POSIX Docker mount paths')


TEMPLATE = '''# Normal NPM generated file
server {
 listen 45451 reuseport;
 listen [::]:45451 reuseport;
 proxy_pass 192.0.2.20:45451;
 access_log /data/logs/stream-1_access.log stream;
 error_log /data/logs/stream-1_error.log warn;
 include /data/nginx/custom/server_stream[.]conf;
 include /data/nginx/custom/server_stream_tcp[.]conf;
}
server {
 listen 45451 udp reuseport;
 listen [::]:45451 udp reuseport;
 proxy_pass 192.0.2.20:45451;
 include /data/nginx/custom/server_stream[.]conf;
 include /data/nginx/custom/server_stream_udp[.]conf;
}
'''


def fixture(tmp_path, monkeypatch):
    data = tmp_path / 'npm-data'
    (data / 'nginx/stream').mkdir(parents=True)
    (data / 'nginx/custom').mkdir()
    (data / 'logs').mkdir()
    (data / 'nginx/stream/1.conf').write_text(TEMPLATE)
    identifier = 'a' * 64
    document = {'Id': identifier, 'Name': '/npm', 'Config': {'Image': 'jc21/nginx-proxy-manager:2.17.1',
                'Labels': {'com.docker.compose.project': 'npm', 'com.docker.compose.service': 'app'}},
                'HostConfig': {'NetworkMode': 'npm_default'}, 'State': {'Running': True, 'Pid': 123},
                'Mounts': [{'Destination': '/data', 'Source': str(data), 'Type': 'bind', 'RW': True}],
                'NetworkSettings': {'Ports': {'45451/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '45451'},
                                                         {'HostIp': '::', 'HostPort': '45451'}]}}}
    calls = []

    def runner(args):
        calls.append(args)
        if args[:2] == ['docker', 'ps']:
            return identifier[:12]
        if args[:2] == ['docker', 'inspect']:
            return json.dumps([document])
        if args[-2:] == ['date', '+%z']:
            return '+0200\n'
        return ''

    monkeypatch.setattr(setup.os, 'readlink', lambda _: 'pid:[4242]')
    return data, document, calls, runner


def test_discovery_understands_real_npm_tcp_ipv6_udp_template(tmp_path, monkeypatch):
    data, _, calls, runner = fixture(tmp_path, monkeypatch)
    stream, = setup.discover_streams(runner)
    assert stream.data_path == data
    assert stream.bindings == (('0.0.0.0', 45451),)
    assert stream.backend_ip == '192.0.2.20' and stream.backend_port == 45451
    assert stream.udp and stream.ipv6 and stream.namespace == 'pid:[4242]'
    assert stream.utc_offset_minutes == 120
    assert not any('reload' in call or 'reopen' in call for call in calls)


@pytest.mark.parametrize('change', [
    lambda text: text.replace('45451 reuseport', '45451 reuseport ssl', 1),
    lambda text: text.replace('server_stream_tcp[.]conf', 'unknown.conf'),
    lambda text: text.replace('192.0.2.20:45451', 'backend.example:45451'),
    lambda text: text.replace('proxy_pass 192.0.2.20:45451;', 'proxy_bind $remote_addr transparent; proxy_pass 192.0.2.20:45451;'),
])
def test_unsupported_stream_is_refused(change):
    with pytest.raises(setup.SetupError):
        setup.parse_stream(change(TEMPLATE))


def test_udp_only_file_is_skipped():
    assert setup.parse_stream(TEMPLATE[TEMPLATE.index('server {', TEMPLATE.index('server {') + 1):]) is None


def test_changed_docker_publication_port_is_not_guessed(tmp_path, monkeypatch):
    _, document, _, runner = fixture(tmp_path, monkeypatch)
    document['NetworkSettings']['Ports']['45451/tcp'][0]['HostPort'] = '45555'
    with pytest.raises(setup.SetupError, match='Разные внешние'):
        setup.discover_streams(runner)


def test_replica_shared_mount_is_refused(tmp_path, monkeypatch):
    _, document, _, base = fixture(tmp_path, monkeypatch)

    def runner(args):
        if args[:2] == ['docker', 'inspect']:
            return json.dumps([document, dict(document, Id='b' * 64)])
        return base(args)

    with pytest.raises(setup.SetupError, match='replicas'):
        setup.discover_streams(runner)


def test_info_append_preserves_existing_bytes_and_rollback(tmp_path, monkeypatch):
    data, _, calls, runner = fixture(tmp_path, monkeypatch)
    include = data / 'nginx/custom/server_stream_tcp.conf'
    previous = b'# operator settings\nproxy_timeout 42s;\n'
    include.write_bytes(previous)
    include.chmod(0o640)
    stream, = setup.discover_streams(runner)
    change = setup.apply_info_logging(stream, tmp_path / 'backup', runner)
    assert include.read_bytes() == previous + setup.BLOCK
    assert (tmp_path / 'backup/server_stream_tcp.conf.original').read_bytes() == previous
    if os.name == 'posix':
        assert include.stat().st_mode & 0o777 == 0o640
        assert (tmp_path / 'backup/server_stream_tcp.conf.original').stat().st_mode & 0o777 == 0o600
    change.rollback()
    assert include.read_bytes() == previous
    assert calls[-1][-3:] == ['nginx', '-s', 'reload']


def test_rollback_never_overwrites_concurrent_operator_edit(tmp_path, monkeypatch):
    data, _, _, runner = fixture(tmp_path, monkeypatch)
    stream, = setup.discover_streams(runner)
    change = setup.apply_info_logging(stream, tmp_path / 'backup', runner)
    include = data / 'nginx/custom/server_stream_tcp.conf'
    include.write_text('# new operator configuration\n')
    with pytest.raises(setup.SetupError, match='другим процессом'):
        change.rollback()
    assert include.read_text() == '# new operator configuration\n'


def test_failed_nginx_validation_restores_prior_include(tmp_path, monkeypatch):
    data, _, _, base = fixture(tmp_path, monkeypatch)
    stream, = setup.discover_streams(base)
    include = data / 'nginx/custom/server_stream_tcp.conf'
    include.write_bytes(b'# existing\n')
    failed = False

    def runner(args):
        nonlocal failed
        if args[-1] == '-t' and setup.BEGIN.encode() in include.read_bytes() and not failed:
            failed = True
            raise setup.SetupError('nginx syntax failure')
        return base(args)

    with pytest.raises(setup.SetupError, match='syntax failure'):
        setup.apply_info_logging(stream, tmp_path / 'backup', runner)
    assert include.read_bytes() == b'# existing\n'


def test_unknown_nested_custom_include_is_not_modified(tmp_path, monkeypatch):
    data, _, _, runner = fixture(tmp_path, monkeypatch)
    include = data / 'nginx/custom/server_stream.conf'
    include.write_text('include /separate/settings.conf;\n')
    with pytest.raises(setup.SetupError, match='custom include'):
        setup.discover_streams(runner)
    assert include.read_text() == 'include /separate/settings.conf;\n'


def test_scope_requires_actual_host_ip_and_published_binding():
    stream = SimpleNamespace(bindings=(('192.0.2.10', 45451),))
    assert setup.choose_scope(stream, '192.0.2.10', ['192.0.2.10']) == '192.0.2.10'
    for ip in ('0.0.0.0', '198.51.100.20', '192.0.2.11'):
        with pytest.raises((setup.SetupError, ValueError)):
            setup.choose_scope(stream, ip, ['192.0.2.10', '192.0.2.11'])


def test_enrollment_commit_is_monitor_only_idempotent_and_excludes_ca_key(tmp_path, monkeypatch):
    from rdp_guard.proxy_pairing import create_pairing
    data, _, _, runner = fixture(tmp_path, monkeypatch)
    stream, = setup.discover_streams(runner)
    pairing = tmp_path / 'pairing'
    create_pairing(pairing, dict(agent_url='https://192.0.2.10:9443', stream_id='npm-1', backend_id='windows',
                   listener_ip='192.0.2.10', listener_port=45451, backend_ip='192.0.2.20', backend_port=45451,
                   relay_ips=['192.0.2.10'], whitelist=['198.51.100.1/32'], protocols=['tcp']))
    plan = dict(stream_id='npm-1', backend_id='windows', listener_ip='192.0.2.10', api_port=9443,
                relay_ips=['192.0.2.10'], whitelist=['198.51.100.1/32'])
    receipt = dict(computer='TEST-WINDOWS', client_sha256='a' * 64)
    destination = tmp_path / 'installed'
    setup.install_enrollment(receipt, stream, plan, pairing, destination=destination)
    cfg = json.loads((destination / 'config.json').read_text())
    assert cfg['enforcement_validated'] is False and cfg['protocols'] == ['tcp']
    assert not (destination / 'ca.key').exists()
    assert str(data / 'logs/rdpguard-stream-info.log') in (destination / 'logrotate.conf').read_text()
    assert stream.container_id in (destination / 'logrotate.conf').read_text()
    setup.install_enrollment(receipt, stream, plan, pairing, destination=destination)
    with pytest.raises(setup.SetupError, match='перезаписывать'):
        setup.install_enrollment(dict(receipt, client_sha256='b' * 64), stream, plan, pairing, destination=destination)


def wizard(tmp_path, monkeypatch, *, acknowledge=True, enroll=True, confirm=True, existing=None, instance=None):
    from rdp_guard import proxy_pairing
    if existing is None:
        data, document, calls, base = fixture(tmp_path, monkeypatch)
    else:
        data, document, calls, base = existing.data, existing.document, existing.calls, existing.base
        (data / 'nginx/stream/2.conf').write_text(TEMPLATE.replace('45451', '45452').replace('192.0.2.20', '192.0.2.21'))
        document['NetworkSettings']['Ports']['45452/tcp'] = [{'HostIp': '0.0.0.0', 'HostPort': '45452'}]
    config, state = tmp_path / 'config', tmp_path / 'state'
    monkeypatch.setattr(setup, 'CONFIG', config)
    monkeypatch.setattr(setup, 'STATE', state)
    monkeypatch.setattr(setup.sys, 'platform', 'linux')
    monkeypatch.setattr(setup.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(setup, 'prepare_state_directory', lambda directory=None:
                        (directory or state).mkdir(mode=0o700, parents=True, exist_ok=True))
    monkeypatch.setattr(setup.socket, 'socket', lambda *_: SimpleNamespace(
        __enter__=lambda self: self, __exit__=lambda *args: None))

    class Probe:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def bind(self, endpoint):
            assert endpoint == ('192.0.2.10', 9444 if existing else 9443)

    monkeypatch.setattr(setup.socket, 'socket', lambda *_: Probe())
    clock, observed = {'now': 0}, []
    monkeypatch.setattr(setup.time, 'monotonic', lambda: clock['now'])

    class Authority:
        def __init__(self, document, directory, callback):
            self.enrolled = None
            self.acknowledged = False
            self.callback = callback
            observed.append(self)

        def close(self):
            pass

    class Server:
        calls = 0
        closed = False

        def handle_request(self):
            self.calls += 1
            authority = observed[0]
            if self.calls == 1 and enroll:
                authority.callback(dict(computer='TEST-WINDOWS', client_sha256='a' * 64))
                authority.enrolled = {'ok': True}
            if self.calls == 3 and acknowledge:
                authority.acknowledged = True
            clock['now'] += 20 if acknowledge else 601

        def server_close(self):
            self.closed = True

    server = Server()
    monkeypatch.setattr(proxy_pairing, 'PairingAuthority', Authority)
    monkeypatch.setattr(proxy_pairing, 'make_pairing_server', lambda *args: server)

    def runner(args):
        if args[:4] == ['ip', '-j', '-4', 'addr']:
            return json.dumps([{'ifname': 'eth0', 'addr_info': [{'scope': 'global', 'local': '192.0.2.10'}]}])
        if args[:4] == ['ip', '-j', '-4', 'route']:
            return json.dumps([{'prefsrc': '192.0.2.10'}])
        if args[:2] == ['systemctl', 'start']:
            assert server.closed  # Pairing and permanent API never overlap.
        return base(args)

    answers = iter(['1', '', '192.0.2.10', '', '', '198.51.100.7/32', 'да', 'ПРИМЕНИТЬ' if confirm else 'нет'])
    output, pairing = [], tmp_path / ((instance or 'windows') + '.rdpg')

    def execute():
        return setup.setup(runner=runner, input_fn=lambda _: next(answers), output=output.append,
                           pairing_file=pairing, instance=instance)

    return SimpleNamespace(execute=execute, config=config, state=state, calls=calls, output=output,
                           pairing=pairing, server=server, data=data, runner=runner, document=document, base=base)


def test_wizard_waits_for_durable_windows_ack_before_start(tmp_path, monkeypatch):
    test = wizard(tmp_path, monkeypatch)
    assert test.execute() == 0
    assert test.server.calls == 3  # Issuance was request one; ACK came 40 seconds later.
    state = json.loads((test.state / 'setup-state.json').read_text())
    assert state['status'] == 'paired' and state['windows_acknowledged']
    assert ['systemctl', 'enable', 'rdpguard-proxy.service'] in test.calls
    assert not test.pairing.exists() and not list(test.state.rglob('ca.key'))
    assert json.loads((test.config / 'config.json').read_text())['enforcement_validated'] is False


def test_expired_issued_receipt_is_not_claimed_as_completed_pairing(tmp_path, monkeypatch):
    test = wizard(tmp_path, monkeypatch, acknowledge=False)
    assert test.execute() == 2
    state = json.loads((test.state / 'setup-state.json').read_text())
    assert state['status'] == 'windows_confirmation_missing' and not state['windows_acknowledged']
    assert ['systemctl', 'start', 'rdpguard-proxy.service'] in test.calls
    assert ['systemctl', 'enable', 'rdpguard-proxy.service'] not in test.calls
    assert any('не подтверждено' in line for line in test.output)
    assert not test.pairing.exists() and not list(test.state.rglob('ca.key'))


def test_expiry_without_enrollment_restores_info_and_leaves_no_config(tmp_path, monkeypatch):
    test = wizard(tmp_path, monkeypatch, acknowledge=False, enroll=False)
    with pytest.raises(setup.SetupError, match='Время привязки'):
        test.execute()
    assert not test.config.exists() and not test.pairing.exists()
    assert not (test.data / 'nginx/custom/server_stream_tcp.conf').exists()
    assert not any(call[:2] == ['systemctl', 'start'] for call in test.calls)
    assert not json.loads((test.state / 'setup-state.json').read_text())['logging_active']


def test_cancelled_review_makes_no_files_or_nginx_reload(tmp_path, monkeypatch):
    test = wizard(tmp_path, monkeypatch, confirm=False)
    assert test.execute() == 0
    assert not test.state.exists() and not test.config.exists() and not test.pairing.exists()
    assert not any('reload' in call for call in test.calls)


def test_unconfigure_restores_exact_include_retains_keys_and_stops_rotation(tmp_path, monkeypatch):
    test = wizard(tmp_path, monkeypatch)
    assert test.execute() == 0
    original_key = (test.config / 'server.key').read_bytes()
    assert setup.unconfigure(runner=test.runner, input_fn=lambda _: 'ВОССТАНОВИТЬ', output=lambda _: None) == 0
    assert not (test.data / 'nginx/custom/server_stream_tcp.conf').exists()
    assert (test.config / 'server.key').read_bytes() == original_key
    assert not json.loads((test.state / 'setup-state.json').read_text())['logging_active']
    assert ['systemctl', 'stop', 'rdpguard-proxy-logrotate.timer'] in test.calls


def test_unconfigure_refuses_concurrent_operator_include_change(tmp_path, monkeypatch):
    test = wizard(tmp_path, monkeypatch)
    assert test.execute() == 0
    path = test.data / 'nginx/custom/server_stream_tcp.conf'
    path.write_bytes(path.read_bytes() + b'# operator change\n')
    before = path.read_bytes()
    with pytest.raises(setup.SetupError, match='изменён после установки'):
        setup.unconfigure(runner=test.runner, input_fn=lambda _: 'ВОССТАНОВИТЬ')
    assert path.read_bytes() == before


def test_doctor_reports_container_namespace_change_without_rebinding(tmp_path, monkeypatch):
    test = wizard(tmp_path, monkeypatch)
    test.execute()
    monkeypatch.setattr(setup.os, 'readlink', lambda _: 'pid:[9999]')
    result = setup.doctor(test.runner)
    assert result['checks']['pid_namespace_matches'] is False
    assert 'перепривязка' in result['recovery']
    assert json.loads((test.config / 'config.json').read_text())['nginx_pid_namespace'] == 'pid:[4242]'


def test_recovery_intent_is_recorded_before_live_include_changes(tmp_path, monkeypatch):
    data, _, _, runner = fixture(tmp_path, monkeypatch)
    stream, = setup.discover_streams(runner)
    include = data / 'nginx/custom/server_stream_tcp.conf'
    seen = []

    def before_change():
        assert not include.exists()
        assert (tmp_path / 'backup/metadata.json').exists()
        seen.append(True)

    setup.apply_info_logging(stream, tmp_path / 'backup', runner, before_change=before_change)
    assert seen == [True] and include.read_bytes() == setup.BLOCK


def test_unconfigure_recovers_intent_if_include_is_already_original(tmp_path, monkeypatch):
    test = wizard(tmp_path, monkeypatch)
    test.execute()
    (test.data / 'nginx/custom/server_stream_tcp.conf').unlink()
    prior_reload_count = sum('reload' in call for call in test.calls)
    assert setup.unconfigure(runner=test.runner, input_fn=lambda _: 'ВОССТАНОВИТЬ', output=lambda _: None) == 0
    assert not json.loads((test.state / 'setup-state.json').read_text())['logging_active']
    assert sum('reload' in call for call in test.calls) == prior_reload_count + 1
