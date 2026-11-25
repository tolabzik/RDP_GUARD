"""Explicit first-install wizard. Discovery is read-only; changes require one review."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time


CONFIG = Path('/etc/rdpguard-proxy')
STATE = Path('/var/lib/rdpguard-proxy')
INFO_PATH = '/data/logs/rdpguard-stream-info.log'
BEGIN = '# BEGIN RDPGUARD PROXY INFO v1'
END = '# END RDPGUARD PROXY INFO v1'
BLOCK = f'{BEGIN}\nerror_log {INFO_PATH} info;\n{END}\n'.encode()
KNOWN_INCLUDES = {'/data/nginx/custom/server_stream[.]conf', '/data/nginx/custom/server_stream_tcp[.]conf',
                  '/data/nginx/custom/server_stream_udp[.]conf'}


class SetupError(RuntimeError):
    pass


def run_command(args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise SetupError(f'{args[0]} failed: {result.stderr[-1000:]}')
    if len(result.stdout) > 8 * 1024 * 1024:
        raise SetupError('Local command output exceeds limit')
    return result.stdout


def ipv4(value):
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local or str(address) == '255.255.255.255':
        raise SetupError('Нужен конкретный IPv4-адрес узла')
    return str(address)


def tokens(text):
    lexer = shlex.shlex(text, posix=True, punctuation_chars='{};')
    lexer.whitespace_split = True
    lexer.commenters = '#'
    result = []
    for token in lexer:
        result.extend(token if token and all(c in '{};' for c in token) else [token])
    return result


def directives(items):
    result, row = [], []
    for token in items:
        if token in '{}':
            raise SetupError('Вложенная или неизвестная nginx-конфигурация не поддерживается')
        if token == ';':
            if row:
                result.append(row)
            row = []
        else:
            row.append(token)
    if row:
        raise SetupError('Незавершённая nginx-директива')
    return result


def parse_stream(text):
    items, servers, pos = tokens(text), [], 0
    while pos < len(items):
        if items[pos:pos + 2] != ['server', '{']:
            raise SetupError('Ожидался обычный NPM server block')
        try:
            end = items.index('}', pos + 2)
        except ValueError:
            raise SetupError('Незавершённый server block') from None
        rows = directives(items[pos + 2:end])
        pos = end + 1
        listens = [row[1:] for row in rows if row[0] == 'listen']
        upstreams = [row[1:] for row in rows if row[0] == 'proxy_pass']
        includes = [row[1] for row in rows if row[0] == 'include' and len(row) == 2]
        if not listens or len(upstreams) != 1 or len(upstreams[0]) != 1:
            raise SetupError('Неоднозначные listen/proxy_pass')
        udp = all('udp' in row[1:] for row in listens)
        if any(('udp' in row[1:]) != udp for row in listens):
            raise SetupError('Смешанный TCP/UDP server не поддерживается')
        expected = '/data/nginx/custom/server_stream_' + ('udp' if udp else 'tcp') + '[.]conf'
        if expected not in includes or any(value not in KNOWN_INCLUDES for value in includes):
            raise SetupError('Неизвестный либо отсутствующий NPM custom include')
        ports, has_v4, has_v6 = set(), False, False
        for row in listens:
            if any(flag not in ('udp', 'reuseport') for flag in row[1:]):
                raise SetupError('TLS/proxy_protocol или необычный listen не поддерживается')
            match = re.fullmatch(r'(?:0\.0\.0\.0:)?(\d+)', row[0])
            match6 = re.fullmatch(r'\[::\]:(\d+)', row[0])
            if match:
                has_v4 = True
            elif match6:
                has_v6 = True
            else:
                raise SetupError('Неизвестный nginx listen address')
            ports.add(int((match or match6)[1]))
        if len(ports) != 1 or not has_v4 or not 1 <= next(iter(ports)) <= 65535:
            raise SetupError('Неоднозначный либо не IPv4 listener')
        match = re.fullmatch(r'([0-9.]+):(\d+)', upstreams[0][0])
        if not match or not 1 <= int(match[2]) <= 65535:
            raise SetupError('Backend должен быть конкретным IPv4:port')
        for row in rows:
            if row[0] not in ('listen', 'proxy_pass', 'include', 'access_log', 'error_log'):
                raise SetupError('Нестандартная stream-директива: ' + row[0])
        servers.append(dict(port=next(iter(ports)), backend_ip=ipv4(match[1]), backend_port=int(match[2]),
                            udp=udp, ipv6=has_v6))
    tcp = [row for row in servers if not row['udp']]
    if not tcp:
        return None
    if len(tcp) != 1:
        raise SetupError('Ожидался один TCP stream')
    result = tcp[0]
    if any(row['port'] != result['port'] or row['backend_ip'] != result['backend_ip']
           or row['backend_port'] != result['backend_port'] for row in servers):
        raise SetupError('TCP и UDP используют разные scopes')
    result['udp'] = any(row['udp'] for row in servers)
    return result


def regular_read(path, limit=1024 * 1024):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise SetupError('Ссылки в путях конфигурации не поддерживаются')
    if not path.is_file() or path.stat().st_size > limit:
        raise SetupError('Нет обычного файла конфигурации либо превышен лимит')
    return path.read_bytes()


def validate_custom(data_path):
    allowed = {'access_log', 'error_log', 'allow', 'deny', 'proxy_connect_timeout', 'proxy_timeout',
               'proxy_socket_keepalive', 'proxy_buffer_size', 'limit_conn'}
    for name in ('server_stream.conf', 'server_stream_tcp.conf'):
        path = data_path / 'nginx/custom' / name
        if path.exists():
            for row in directives(tokens(regular_read(path).decode('utf-8'))):
                if row[0] not in allowed:
                    raise SetupError('Неподдерживаемая директива в custom include: ' + row[0])


@dataclass(frozen=True)
class Stream:
    container_id: str
    container_name: str
    data_path: Path
    config_path: Path
    backend_ip: str
    backend_port: int
    container_port: int
    bindings: tuple[tuple[str, int], ...]
    udp: bool
    ipv6: bool
    namespace: str
    utc_offset_minutes: int


def discover_streams(runner=run_command, proc_root=Path('/proc')):
    ids = runner(['docker', 'ps', '--filter', 'status=running', '--format', '{{.ID}}']).split()
    if any(not re.fullmatch(r'[a-f0-9]{12,64}', value) for value in ids) or len(ids) > 64:
        raise SetupError('Неоднозначный список Docker containers')
    containers = json.loads(runner(['docker', 'inspect', *ids])) if ids else []
    result, seen_mounts, seen_services = [], set(), set()
    for container in containers:
        image = container.get('Config', {}).get('Image', '').removeprefix('docker.io/')
        if not (image.startswith('jc21/nginx-proxy-manager:') or image.startswith('jc21/nginx-proxy-manager@')):
            continue
        identifier = container['Id']
        if not re.fullmatch(r'[a-f0-9]{64}', identifier) or container.get('State', {}).get('Running') is not True:
            raise SetupError('NPM container identity недоступна')
        if container.get('HostConfig', {}).get('NetworkMode') in ('host', 'none'):
            raise SetupError('Поддерживается опубликованный Docker bridge listener')
        mounts = [item for item in container.get('Mounts', []) if item.get('Destination') == '/data']
        if len(mounts) != 1 or mounts[0].get('Type') not in ('bind', 'volume') or not mounts[0].get('RW'):
            raise SetupError('Нужен один доступный read/write mount /data')
        data = Path(mounts[0]['Source'])
        if (not data.is_absolute() or not data.is_dir() or data.is_symlink()
                or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(data))):
            raise SetupError('Docker /data host mount недоступен')
        labels = container.get('Config', {}).get('Labels') or {}
        service = (labels.get('com.docker.compose.project'), labels.get('com.docker.compose.service'))
        if str(data) in seen_mounts or (all(service) and service in seen_services):
            raise SetupError('NPM replicas/shared mount не поддерживаются')
        seen_mounts.add(str(data))
        if all(service):
            seen_services.add(service)
        pid = container['State'].get('Pid')
        if type(pid) is not int or pid <= 0:
            raise SetupError('NPM host PID недоступен')
        namespace = os.readlink(proc_root / str(pid) / 'ns/pid')
        if not re.fullmatch(r'pid:\[\d+\]', namespace):
            raise SetupError('Неверный PID namespace')
        zone = runner(['docker', 'exec', identifier, 'date', '+%z']).strip()
        if not re.fullmatch(r'[+-]\d{4}', zone) or int(zone[3:]) > 59:
            raise SetupError('Не удалось определить часовой пояс nginx')
        offset = (int(zone[1:3]) * 60 + int(zone[3:])) * (-1 if zone[0] == '-' else 1)
        if abs(offset) > 840:
            raise SetupError('Неверный часовой пояс nginx')
        validate_custom(data)
        runner(['docker', 'exec', identifier, 'nginx', '-t'])
        for path in sorted((data / 'nginx/stream').glob('*.conf')):
            text = regular_read(path).decode('utf-8')
            if not tokens(text):
                continue
            parsed = parse_stream(text)
            if parsed is None:
                continue
            if not path.stem.isdigit():
                raise SetupError('Ожидался числовой идентификатор NPM stream')
            key = str(parsed['port']) + '/tcp'
            publications = container.get('NetworkSettings', {}).get('Ports', {}).get(key) or []
            bindings = []
            for row in publications:
                try:
                    host = str(ipaddress.IPv4Address(row['HostIp']))
                except ipaddress.AddressValueError:
                    continue
                port = int(row['HostPort'])
                if port != parsed['port']:
                    raise SetupError('Разные внешние и внутренние TCP-порты Docker пока не поддерживаются')
                bindings.append((host, port))
            if not bindings:
                continue
            result.append(Stream(identifier, container.get('Name', '').lstrip('/'), data, path,
                                 parsed['backend_ip'], parsed['backend_port'], parsed['port'],
                                 tuple(sorted(set(bindings))), parsed['udp'], parsed['ipv6'], namespace, offset))
    if not result:
        raise SetupError('Не найден поддерживаемый опубликованный TCP stream NPM')
    scopes = [(host, port) for stream in result for host, port in stream.bindings]
    if len(scopes) != len(set(scopes)):
        raise SetupError('Несколько NPM streams используют один listener')
    return result


def atomic_write(path, data, mode=0o600, owner=None):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            os.chmod(temporary, mode)
            if owner is not None and os.name == 'posix':
                os.fchown(file.fileno(), *owner)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sync_directory(path):
    if os.name == 'posix':
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class IncludeChange:
    def __init__(self, stream, path, before, applied, runner, mode=0o644, owner=None):
        self.stream, self.path, self.before, self.applied, self.runner = stream, path, before, applied, runner
        self.mode, self.owner = mode, owner

    def rollback(self):
        if regular_read(self.path) != self.applied:
            raise SetupError('Custom include изменён другим процессом: автоматический откат запрещён')
        if self.before is None:
            self.path.unlink()
        else:
            atomic_write(self.path, self.before, self.mode, self.owner)
        self.runner(['docker', 'exec', self.stream.container_id, 'nginx', '-t'])
        self.runner(['docker', 'exec', self.stream.container_id, 'nginx', '-s', 'reload'])


def apply_info_logging(stream, backup_dir, runner=run_command, *, before_change=None):
    validate_custom(stream.data_path)
    path = stream.data_path / 'nginx/custom/server_stream_tcp.conf'
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    before = regular_read(path) if path.exists() else None
    stat = path.stat() if before is not None else None
    mode, owner = (stat.st_mode & 0o777, (stat.st_uid, stat.st_gid)) if stat else (0o644, None)
    if before is not None and (BEGIN.encode() in before or END.encode() in before):
        raise SetupError('Managed INFO block уже существует: сначала проверьте предыдущую установку')
    backup_dir.mkdir(mode=0o700)
    if before is not None:
        atomic_write(backup_dir / 'server_stream_tcp.conf.original', before)
    atomic_write(backup_dir / 'metadata.json', json.dumps({'path': str(path), 'existed': before is not None,
                 'mode': mode, 'owner': owner,
                 'sha256': hashlib.sha256(before or b'').hexdigest()}).encode())
    runner(['docker', 'exec', stream.container_id, 'nginx', '-t'])
    applied = (before or b'') + (b'\n' if before and not before.endswith(b'\n') else b'') + BLOCK
    if (regular_read(path) if path.exists() else None) != before:
        raise SetupError('Custom include изменился во время подготовки')
    if before_change is not None:
        before_change()  # Persist recovery intent before changing the live include.
    atomic_write(path, applied, mode, owner)
    change = IncludeChange(stream, path, before, applied, runner, mode, owner)
    try:
        runner(['docker', 'exec', stream.container_id, 'nginx', '-t'])
        runner(['docker', 'exec', stream.container_id, 'nginx', '-s', 'reload'])
    except Exception:
        change.rollback()
        raise
    return change


def host_addresses(runner=run_command):
    values = []
    for interface in json.loads(runner(['ip', '-j', '-4', 'addr', 'show', 'scope', 'global'])):
        if interface.get('ifname', '').startswith(('docker', 'veth', 'br-')):
            continue
        for item in interface.get('addr_info', []):
            if item.get('scope') == 'global':
                values.append(ipv4(item['local']))
    return sorted(set(values))


def choose_scope(stream, listener, available):
    listener = ipv4(listener)
    if listener not in available or not any(ip in ('0.0.0.0', listener) for ip, _ in stream.bindings):
        raise SetupError('IPv4 должен принадлежать хосту и выбранной Docker publication')
    return listener


def local_status(runner=run_command, *, instance=None):
    from .proxy_instances import Instance
    item = Instance(CONFIG, STATE, instance)
    try:
        return runner(['systemctl', 'status', '--no-pager', item.unit])
    except SetupError as exc:
        return str(exc)


def doctor(runner=run_command, *, instance=None):
    from .proxy_agent import load_config
    from .proxy_instances import Instance
    item = Instance(CONFIG, STATE, instance)
    result = {'configured': (item.config / 'config.json').is_file(), 'enforcement_allowed': False, 'checks': {}, 'instance': item.label, 'service': item.unit}
    if result['configured']:
        config = load_config(json.loads(regular_read(item.config / 'config.json')))
        result['enforcement_allowed'] = config['enforcement_validated']
        result['checks']['configuration'] = True
        result['checks']['log_exists'] = Path(config['nginx_log']).is_file()
    if (item.state / 'setup-state.json').exists():
        result['setup'] = json.loads(regular_read(item.state / 'setup-state.json'))
    try:
        streams = discover_streams(runner)
        result['checks']['npm_streams'] = len(streams)
        if result['configured']:
            selected = [s for s in streams if s.backend_ip == config['backend_ip']
                        and s.backend_port == config['backend_port']
                        and s.container_port == config['listener_port']
                        and str(s.data_path / 'logs/rdpguard-stream-info.log') == config['nginx_log']]
            result['checks']['configured_scope_found'] = len(selected) == 1
            result['checks']['pid_namespace_matches'] = (len(selected) == 1
                and selected[0].namespace == config['nginx_pid_namespace'])
            if not result['checks']['pid_namespace_matches']:
                result['recovery'] = ('NPM container/PID namespace изменился или scope не найден. '
                    'Наблюдение недоступно; нужна проверенная перепривязка namespace и перезапуск агента. '
                    'Мастер не меняет привязку автоматически.')
    except (OSError, ValueError, SetupError) as exc:
        result['checks']['npm_error'] = str(exc)
    return result


def save_setup_state(*, directory=None, **values):
    path = (STATE if directory is None else directory) / 'setup-state.json'
    previous = json.loads(regular_read(path)) if path.exists() else {}
    atomic_write(path, json.dumps(dict(previous, schema='rdpguard.proxy-setup.v1', **values), indent=2).encode())


def unconfigure(*, runner=run_command, input_fn=input, output=print, instance=None):
    """Detach this instance; only the last log user restores the managed include."""
    from .proxy_instances import Instance, inventory, logging_backup, logging_users, release_logging
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SetupError('Нужен root на Linux-хосте NPM')
    item = Instance(CONFIG, STATE, instance)
    state = json.loads(regular_read(item.state / 'setup-state.json'))
    if state.get('logging_active') is not True:
        output('Managed INFO logging уже отключён. Ключи и данные сохранены.')
        return 0
    _, _, path, original, applied, identity = logging_backup(item, state)
    users = logging_users(item, path, exclude_self=True)
    current = regular_read(path) if path.exists() else None
    if current != applied and (users or current != original):
        raise SetupError('Include изменён после установки: автоматическое восстановление запрещено')
    runner(['docker', 'exec', identity, 'nginx', '-t'])
    output(f'Будет остановлен узел {item.label}. Ключи и SQLite сохраняются. ' +
           ('Общий INFO-журнал остаётся для других узлов.' if users else f'Будет восстановлен исходный {path}.'))
    if prompt('Подтвердите: ВОССТАНОВИТЬ', None, input_fn) != 'ВОССТАНОВИТЬ':
        return 0
    runner(['systemctl', 'stop', item.unit])
    release_logging(item, runner)
    runner(['systemctl', 'disable', item.unit])
    if not any(state.get('logging_active') for _, _, state in inventory(CONFIG, STATE)):
        runner(['systemctl', 'stop', 'rdpguard-proxy-logrotate.timer'])
        runner(['systemctl', 'disable', 'rdpguard-proxy-logrotate.timer'])
    output('Узел отключён; ключи и данные сохранены. Остальные узлы не остановлены.')
    return 0


def install_enrollment(receipt, stream, plan, pairing_dir, *, destination=None, state_directory=None):
    """Commit all service credentials/config together; never copy the CA private key."""
    from .proxy_agent import load_config
    destination = CONFIG if destination is None else destination
    config = load_config({
        'schema': 'rdpguard.proxy-agent.v1', 'stream_id': plan['stream_id'], 'backend_id': plan['backend_id'],
        'computer': receipt['computer'], 'client_sha256': receipt['client_sha256'],
        'api_host': plan['listener_ip'], 'api_port': plan['api_port'],
        'ca_file': str(destination / 'ca.pem'), 'cert_file': str(destination / 'server.pem'),
        'key_file': str(destination / 'server.key'), 'nginx_log': str(stream.data_path / 'logs/rdpguard-stream-info.log'),
        'backend_ip': stream.backend_ip, 'backend_port': stream.backend_port,
        'listener_ip': plan['listener_ip'], 'listener_port': stream.container_port,
        'relay_ips': plan['relay_ips'], 'nginx_utc_offset_minutes': stream.utc_offset_minutes,
        'nginx_pid_namespace': stream.namespace, 'whitelist': plan['whitelist'],
        'state_file': str((state_directory or STATE) / 'state.sqlite3'), 'enforcement_validated': False, 'protocols': ['tcp'],
    })
    if destination.exists():
        existing = json.loads(regular_read(destination / 'config.json'))
        if existing == config and all(regular_read(destination / name) == regular_read(pairing_dir / name)
                                      for name in ('ca.pem', 'server.pem', 'server.key')):
            return  # Callback retry for the same reserved enrollment.
        raise SetupError('Другую установленную привязку перезаписывать нельзя')
    temporary = Path(tempfile.mkdtemp(prefix='.rdpguard-proxy-', dir=destination.parent))
    try:
        os.chmod(temporary, 0o700)
        for name in ('ca.pem', 'server.pem', 'server.key'):
            atomic_write(temporary / name, regular_read(pairing_dir / name))
        log = stream.data_path / 'logs/rdpguard-stream-info.log'
        rotation = (f'\"{log}\" {{\n  size 16M\n  rotate 7\n  missingok\n  notifempty\n'
                    '  compress\n  delaycompress\n  nocreate\n  sharedscripts\n  postrotate\n'
                    f'    /usr/bin/docker exec {stream.container_id} nginx -s reopen >/dev/null 2>&1\n'
                    '  endscript\n}\n')
        atomic_write(temporary / 'logrotate.conf', rotation.encode())
        atomic_write(temporary / 'config.json', json.dumps(config, indent=2).encode())
        if destination.exists():
            raise SetupError('Каталог конфигурации появился во время привязки')
        sync_directory(temporary)
        temporary.rename(destination)
        sync_directory(destination.parent)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def prompt(text, default=None, input_fn=input):
    answer = input_fn(text + (f' [{default}]' if default is not None else '') + ': ').strip()
    return answer if answer else default


def prepare_state_directory(directory=None):
    directory = STATE if directory is None else directory
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(path.is_symlink() for path in (directory, *directory.parents)) or directory.stat().st_uid != 0:
        raise SetupError('Каталог состояния должен принадлежать root и не быть ссылкой')
    os.chmod(directory, 0o700)


def setup(*, runner=run_command, input_fn=input, output=print, pairing_file=None, instance=None):
    from .proxy_instances import (Instance, inventory, validate_available, next_api_port,
                                  acquire_logging, release_logging)
    item = Instance(CONFIG, STATE, instance)
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SetupError('Запустите sudo rdpguard-proxy setup на Linux-хосте NPM')
    if item.config.exists() or Path('/opt/rdpguard-proxy').exists() or (item.state / 'state.sqlite3').exists():
        raise SetupError('Существующая установка обнаружена; для неё используйте status/doctor, не новую привязку')
    streams = discover_streams(runner)
    all_streams = streams
    configured = [cfg for _, cfg, _ in inventory(CONFIG, STATE) if cfg]
    if instance is not None:
        streams = [s for s in streams if not any((s.backend_ip, s.backend_port) ==
                   (cfg['backend_ip'], cfg['backend_port']) for cfg in configured)]
        if not streams:
            raise SetupError('Все поддерживаемые streams уже привязаны; сначала добавьте новый stream в NPM')
    for number, stream in enumerate(streams, 1):
        output(f'{number}. {stream.container_name}: TCP {stream.container_port} → '
               f'{stream.backend_ip}:{stream.backend_port}'
               + ('; UDP существует, но не выбирается' if stream.udp else ''))
    choice = prompt('Номер stream', '1' if len(streams) == 1 else None, input_fn)
    if choice is None or not choice.isdigit() or not 1 <= int(choice) <= len(streams):
        raise SetupError('Неверный номер stream')
    stream = streams[int(choice) - 1]
    available = host_addresses(runner)
    candidates = [address for address in available if any(bound in ('0.0.0.0', address) for bound, _ in stream.bindings)]
    output('IPv4 адреса этого хоста: ' + ', '.join(candidates))
    listener = choose_scope(stream, prompt('Конкретный IP входа RDP', candidates[0] if len(candidates) == 1 else None,
                                          input_fn), available)
    default_api = listener if ipaddress.ip_address(listener).is_global else None
    advertised = ipv4(prompt('IPv4 агента, доступный Windows по HTTPS', default_api, input_fn))
    rdp_ports = [s.container_port for s in all_streams
                 if any(ip in ('0.0.0.0', listener) for ip, _ in s.bindings)]
    port_text = prompt('Отдельный HTTPS-порт агента', str(next_api_port(item, listener, rdp_ports)), input_fn)
    if not port_text or not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise SetupError('Неверный HTTPS-порт')
    api_port = int(port_text)
    if api_port in rdp_ports:
        raise SetupError('HTTPS API и RDP должны использовать разные порты')
    routes = json.loads(runner(['ip', '-j', '-4', 'route', 'get', stream.backend_ip]))
    default_relay = routes[0].get('prefsrc') if len(routes) == 1 else None
    relay = ipv4(prompt('IP прокси, который виден в Windows (проверьте событие 131)', default_relay, input_fn))
    from .models import network
    networks = prompt('Ваши реальные внешние IP/CIDR администраторов через запятую (не IP прокси)', None, input_fn)
    if not networks:
        raise SetupError('Укажите хотя бы один адрес администратора')
    whitelist = sorted({network(item.strip()) for item in networks.split(',')})
    if any(item in (relay + '/32', listener + '/32') for item in whitelist):
        raise SetupError('В whitelist нужны адреса администраторов, а не самого прокси')
    enable = prompt('Включить автозапуск после успешной привязки? да/нет', 'нет', input_fn).lower() in ('да', 'yes', 'y')
    plan = dict(stream_id=f'npm-{stream.config_path.stem}-{stream.container_port}', backend_id=f'windows-{stream.container_port}',
                listener_ip=listener, api_port=api_port, relay_ips=[relay], whitelist=whitelist,
                agent_url=f'https://{advertised}:{api_port}', enable=enable)
    if instance is not None:
        plan['stream_id'] = instance
        plan['backend_id'] = instance
    validate_available(item, stream, listener, api_port, plan['stream_id'])
    destination = Path(pairing_file) if pairing_file else Path(f'/root/rdpguard-{instance or stream.container_port}.rdpg')
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise SetupError('Выберите новый абсолютный путь для единственного .rdpg файла')
    # Checking a port does not expose a server or send any remote packet.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((listener, api_port))
    output('\nБудет настроено: ' + json.dumps(plan, ensure_ascii=False, indent=2))
    output('INFO include применяется ко ВСЕМ TCP streams; включается отдельная ротация 16 MiB/7 файлов, проверка каждые 5 минут. '
           'Генерируемые конфиги и firewall не меняются. IPv6/UDP не защищаются этой привязкой.')
    output(f'Файл для Windows: {destination}. Окно привязки 10 минут. После неё агент запускается только в monitor.')
    if prompt('Применить этот план? Введите ПРИМЕНИТЬ', None, input_fn) != 'ПРИМЕНИТЬ':
        output('Отменено. Изменений нет.')
        return 0
    # Re-read immutable scope before changing anything; a restarted/replaced
    # container or changed upstream must be reviewed as a new plan.
    if stream not in discover_streams(runner):
        raise SetupError('NPM scope изменился после просмотра плана; запустите мастер заново')
    prepare_state_directory()
    if instance is not None:
        prepare_state_directory(item.state)
        prepare_state_directory(item.config.parent)
    work = Path(tempfile.mkdtemp(prefix='setup-', dir=item.state))
    pairing_dir = work / 'pairing'
    authority, server, committed = None, None, False
    pairing_bytes = None
    from .proxy_pairing import create_pairing, PairingAuthority, make_pairing_server
    try:
        settings = {key: plan[key] for key in ('agent_url', 'stream_id', 'backend_id', 'listener_ip', 'relay_ips', 'whitelist')}
        settings.update(listener_port=stream.container_port, backend_ip=stream.backend_ip,
                        backend_port=stream.backend_port, protocols=['tcp'])
        document = create_pairing(pairing_dir, settings)

        def on_enrolled(receipt):
            nonlocal committed
            install_enrollment(receipt, stream, plan, pairing_dir, destination=item.config, state_directory=item.state)
            committed = True

        authority = PairingAuthority(document, pairing_dir, on_enrolled)
        server = make_pairing_server(authority, listener, api_port)
        acquire_logging(item, stream, work / 'nginx-backup', runner)
        payload = json.dumps(document, ensure_ascii=True, indent=2).encode()
        with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as file:
            file.write(payload)
            pairing_bytes = payload
        output(f'Передайте {destination} нужному Windows-серверу и импортируйте в разделе «Прокси». '
               'Оставьте это окно открытым. Файл содержит одноразовый секрет.')
        until = time.monotonic() + max(0, document['expires_at'] - time.time())
        while not authority.acknowledged and time.monotonic() < until:
            server.handle_request()
        if not committed:
            raise SetupError('Время привязки истекло. Новый запуск создаст новый одноразовый файл.')
        server.server_close()
        server = None
        save_setup_state(directory=item.state, status='paired' if authority.acknowledged else 'windows_confirmation_missing',
                         windows_acknowledged=authority.acknowledged)
        # NPM keeps writing even if an agent is stopped or has autostart disabled.
        runner(['systemctl', 'enable', '--now', 'rdpguard-proxy-logrotate.timer'])
        runner(['systemctl', 'start', item.unit])
        if enable and authority.acknowledged:
            runner(['systemctl', 'enable', item.unit])
        if not authority.acknowledged:
            output('Linux-привязка сохранена, но Windows не подтвердил сохранение сертификата. '
                   'Monitor запущен для уже сохранённого клиента; завершение настройки не подтверждено. '
                   'Проверьте статус Windows. Если сертификат не сохранён, нужна новая привязка; '
                   'истёкший файл использовать нельзя. Автозапуск не включён.')
            return 2
        output('Привязка сохранена. Linux-агент запущен в monitor; блокировки не разрешены. '
               'Проверьте статус в Windows. Для наблюдения общий ACTIVE не нужен.')
        return 0
    finally:
        if server is not None:
            server.server_close()
        if authority is not None:
            authority.close()
        if pairing_bytes is not None and destination.exists() and regular_read(destination) == pairing_bytes:
            destination.unlink()
        if pairing_dir.exists():
            shutil.rmtree(pairing_dir)
        if not committed and (item.state / 'setup-state.json').exists():
            state = json.loads(regular_read(item.state / 'setup-state.json'))
            if state.get('logging_active'):
                release_logging(item, runner)
                save_setup_state(directory=item.state, logging_active=False, status='cancelled')


def main(argv=None):
    from .proxy_instances import inventory, instance_name, management_lock, rotate_logs
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    setup_parser = commands.add_parser('setup', help='Мастер новой установки и одноразовой привязки Windows')
    setup_parser.add_argument('--pairing-file', help='Новый абсолютный путь для .rdpg')
    setup_parser.add_argument('--instance', help='Имя нового экземпляра')
    add_parser = commands.add_parser('add', help='Добавить ещё один Windows, сохраняя существующие узлы')
    add_parser.add_argument('--instance', help='Имя нового экземпляра')
    add_parser.add_argument('--pairing-file', help='Новый абсолютный путь для .rdpg')
    commands.add_parser('list', help='Список всех привязок без секретов')
    commands.add_parser('rotate-logs', help='Общая ротация INFO-журналов (вызывается таймером)')
    for command, help_text in (('status', 'Состояние служб'), ('doctor', 'Локальные проверки без изменений'),
                               ('unconfigure', 'Отключить один узел, сохранив ключи и остальные узлы')):
        child = commands.add_parser(command, help=help_text)
        child.add_argument('--instance', help='Имя экземпляра; default для прежней одиночной установки')
    args = parser.parse_args(argv)
    try:
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise SetupError('Нужен root на Linux-хосте NPM')
        if args.command == 'rotate-logs':
            # A ten-minute pairing must not suspend rotation for existing nodes.
            # Config files are committed atomically and retained on unconfigure.
            with management_lock(Path('/run/rdpguard-proxy-rotation.lock')):
                rotate_logs(CONFIG, STATE, run_command)
            return 0
        if args.command in ('setup', 'add', 'unconfigure', 'rotate-logs'):
            with management_lock():
                entries = inventory(CONFIG, STATE)
                if args.command == 'unconfigure':
                    if args.instance is None and len(entries) > 1:
                        raise SetupError('Укажите --instance ИМЯ (список: rdpguard-proxy list)')
                    selected = (args.instance if args.instance != 'default' else None)
                    if args.instance is None and len(entries) == 1:
                        selected = entries[0][0].name
                    return unconfigure(instance=selected)
                selected = args.instance
                if args.command == 'add' or (args.command == 'setup' and entries and selected is None):
                    selected = selected or prompt('Имя нового узла', f'windows-{len(entries) + 1}')
                    instance_name(selected)
                return setup(pairing_file=args.pairing_file, instance=selected)
        entries = inventory(CONFIG, STATE)
        if args.command == 'list':
            rows = []
            for item, config, state in entries:
                rows.append({'instance': item.label, 'service': item.unit, 'status': state.get('status', 'manual'),
                             'computer': config['computer'] if config else None,
                             'listener': f"{config['listener_ip']}:{config['listener_port']}" if config else None,
                             'api_port': config['api_port'] if config else None,
                             'enforcement_allowed': config['enforcement_validated'] if config else False})
            print(json.dumps(rows, ensure_ascii=False, indent=2))
            return 0
        selected = getattr(args, 'instance', None)
        names = ([None if selected == 'default' else instance_name(selected)] if selected is not None else
                 [item.name for item, _, _ in entries] or [None])
        if args.command == 'status':
            for name in names:
                print(local_status(instance=name))
        else:
            results = [doctor(instance=name) for name in names]
            print(json.dumps(results[0] if len(results) == 1 else results, ensure_ascii=False, indent=2))
        return 0
    except (SetupError, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        print('Настройка не завершена: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
