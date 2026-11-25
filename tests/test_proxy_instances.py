"""Multiple backends must not share credentials, firewall scope or lifecycle."""
from dataclasses import replace
import json
import os

import pytest

from rdp_guard import proxy_instances as instances
from rdp_guard import proxy_setup as setup
from test_proxy_setup import wizard

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Linux management paths')


def nodes(tmp_path, monkeypatch):
    first = wizard(tmp_path, monkeypatch)
    first.execute()
    # Simulate an already accepted, active customer's configuration.
    config = first.config / 'config.json'
    data = json.loads(config.read_text())
    data['enforcement_validated'] = True
    config.write_text(json.dumps(data))
    before = {p.name: p.read_bytes() for p in first.config.iterdir()}
    second = wizard(tmp_path, monkeypatch, existing=first, instance='accounting')
    second.execute()
    assert before == {p.name: p.read_bytes() for p in first.config.iterdir() if p.is_file()}
    item = instances.Instance(first.config, first.state, 'accounting')
    return first, second, item


def test_add_keeps_active_legacy_binding_and_has_independent_credentials(tmp_path, monkeypatch):
    first, second, item = nodes(tmp_path, monkeypatch)
    config = json.loads((item.config / 'config.json').read_text())
    original = json.loads((first.config / 'config.json').read_text())
    assert config['api_port'] == 9444 and original['api_port'] == 9443
    assert config['listener_port'] == 45452 and original['listener_port'] == 45451
    assert config['stream_id'] != original['stream_id']
    assert config['state_file'] == str(item.state / 'state.sqlite3')
    assert config['state_file'] != original['state_file']
    assert not config['enforcement_validated'] and original['enforcement_validated']
    for name in ('ca.pem', 'server.pem', 'server.key'):
        assert (item.config / name).read_bytes() != (first.config / name).read_bytes()
    assert sum('reload' in call for call in second.calls) == 1
    assert ['systemctl', 'start', item.unit] in second.calls
    assert ['systemctl', 'stop', 'rdpguard-proxy.service'] not in second.calls
    assert (second.data / 'nginx/custom/server_stream_tcp.conf').read_bytes() == setup.BLOCK


@pytest.mark.parametrize('legacy_first', [False, True])
def test_remove_one_node_keeps_shared_log_then_last_restores_original(tmp_path, monkeypatch, legacy_first):
    first, second, item = nodes(tmp_path, monkeypatch)
    retained = (item.config / 'server.key').read_bytes()
    first_name, last_name = (None, 'accounting') if legacy_first else ('accounting', None)
    before = len(second.calls)
    setup.unconfigure(instance=first_name, runner=second.runner, input_fn=lambda _: 'ВОССТАНОВИТЬ', output=lambda _: None)
    assert not any('reload' in call for call in second.calls[before:])
    assert (second.data / 'nginx/custom/server_stream_tcp.conf').read_bytes() == setup.BLOCK
    other_unit = item.unit if legacy_first else 'rdpguard-proxy.service'
    assert ['systemctl', 'stop', other_unit] not in second.calls[before:]
    assert not any('rdpguard-proxy-logrotate.timer' in call for call in second.calls[before:])
    setup.unconfigure(instance=last_name, runner=second.runner, input_fn=lambda _: 'ВОССТАНОВИТЬ', output=lambda _: None)
    assert not (second.data / 'nginx/custom/server_stream_tcp.conf').exists()
    assert (item.config / 'server.key').read_bytes() == retained
    assert ['systemctl', 'stop', 'rdpguard-proxy-logrotate.timer'] in second.calls[before:]


def test_cancelled_second_pairing_does_not_roll_back_first_logging(tmp_path, monkeypatch):
    first = wizard(tmp_path, monkeypatch)
    first.execute()
    second = wizard(tmp_path, monkeypatch, existing=first, instance='accounting', acknowledge=False, enroll=False)
    before = len(second.calls)
    with pytest.raises(setup.SetupError, match='Время привязки'):
        second.execute()
    assert (first.data / 'nginx/custom/server_stream_tcp.conf').read_bytes() == setup.BLOCK
    assert not (first.config / 'instances/accounting').exists()
    assert not any('reload' in call or call[0] == 'systemctl' for call in second.calls[before:])
    assert json.loads((first.state / 'setup-state.json').read_text())['logging_active']


def test_rotation_runs_once_for_shared_log_even_after_first_unconfigure(tmp_path, monkeypatch):
    first, second, _ = nodes(tmp_path, monkeypatch)
    calls = []
    instances.rotate_logs(first.config, first.state, calls.append)
    assert len(calls) == 1
    assert calls[0][2] == str(first.state / 'logrotate.status')
    setup.unconfigure(runner=second.runner, input_fn=lambda _: 'ВОССТАНОВИТЬ', output=lambda _: None)
    calls.clear()
    instances.rotate_logs(first.config, first.state, calls.append)
    assert len(calls) == 1
    assert calls[0][2] == str(first.state / 'logrotate.status')
    assert calls[0][3] == str(first.config / 'instances/accounting/logrotate.conf')


def test_conflicting_rotation_is_rejected_before_any_logrotate(tmp_path, monkeypatch):
    first, _, item = nodes(tmp_path, monkeypatch)
    (item.config / 'logrotate.conf').write_text('different rotation')
    calls = []
    with pytest.raises(setup.SetupError, match='Несогласованные'):
        instances.rotate_logs(first.config, first.state, calls.append)
    assert calls == []


@pytest.mark.parametrize('collision', ['listener', 'backend', 'api', 'stream'])
def test_duplicate_scopes_are_rejected_before_pairing(tmp_path, monkeypatch, collision):
    first, second, _ = nodes(tmp_path, monkeypatch)
    item = instances.Instance(first.config, first.state, 'third')
    stream = replace(setup.discover_streams(second.runner)[0], backend_ip='192.0.2.22', container_port=45453)
    api_port, stream_id = 9445, 'third'
    if collision == 'listener':
        stream = replace(stream, container_port=45451)
    elif collision == 'backend':
        stream = replace(stream, backend_ip='192.0.2.20')
    elif collision == 'api':
        api_port = 9443
    else:
        stream_id = 'accounting'
    with pytest.raises(setup.SetupError):
        instances.validate_available(item, stream, '192.0.2.10', api_port, stream_id)


@pytest.mark.parametrize('name', ['default', '../node', '-a', 'bad/name', 'имя', 'A', 'a' * 33, 'a.service'])
def test_instance_names_cannot_escape_paths_or_units(name):
    with pytest.raises(setup.SetupError):
        instances.instance_name(name)


def test_management_lock_excludes_another_setup_but_not_rotation(tmp_path):
    with instances.management_lock(tmp_path / 'management'):
        with pytest.raises(setup.SetupError, match='Другой мастер'):
            with instances.management_lock(tmp_path / 'management'):
                pytest.fail('Second writer entered')
        with instances.management_lock(tmp_path / 'rotation'):
            pass


def test_list_and_doctor_identify_each_instance_without_secrets(tmp_path, monkeypatch, capsys):
    first, second, item = nodes(tmp_path, monkeypatch)
    assert setup.main(['list']) == 0
    result = capsys.readouterr().out
    rows = json.loads(result)
    assert [row['instance'] for row in rows] == ['default', 'accounting']
    assert rows[1]['service'] == item.unit
    assert 'PRIVATE KEY' not in result and 'client_sha256' not in result
    result = setup.doctor(second.runner, instance='accounting')
    assert result['checks']['configured_scope_found'] and result['service'] == item.unit
    assert not result['enforcement_allowed']


def test_named_first_install_needs_no_legacy_config_or_rotation_file(tmp_path, monkeypatch):
    first = wizard(tmp_path, monkeypatch, instance='accounting')
    first.execute()
    assert not (first.config / 'config.json').exists()
    item, cfg, state = instances.inventory(first.config, first.state)[0]
    assert item.name == 'accounting' and cfg['api_port'] == 9443 and state['logging_active']
    calls = []
    instances.rotate_logs(first.config, first.state, calls.append)
    assert len(calls) == 1 and calls[0][-1] == str(item.config / 'logrotate.conf')
    setup.unconfigure(instance='accounting', runner=first.runner, input_fn=lambda _: 'ВОССТАНОВИТЬ', output=lambda _: None)
    assert not (first.data / 'nginx/custom/server_stream_tcp.conf').exists()


def test_adding_node_refuses_modified_shared_include_without_stopping_first(tmp_path, monkeypatch):
    first = wizard(tmp_path, monkeypatch)
    first.execute()
    include = first.data / 'nginx/custom/server_stream_tcp.conf'
    changed = include.read_bytes() + b'# administrator edit\n'
    include.write_bytes(changed)
    second = wizard(tmp_path, monkeypatch, existing=first, instance='accounting')
    before = len(second.calls)
    with pytest.raises(setup.SetupError, match='Общий INFO'):
        second.execute()
    assert include.read_bytes() == changed
    assert not any(call[0] == 'systemctl' or 'reload' in call for call in second.calls[before:])
    assert not (first.config / 'instances/accounting/config.json').exists()
