"""Named local agents and shared NPM logging ownership; no remote control API."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re


MAX_INSTANCES = 32


def instance_name(value):
    from .proxy_setup import SetupError
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', value) or value == 'default':
        raise SetupError('Имя узла: 1–32 символа a-z, 0-9, дефис; начало — буква; default зарезервировано')
    return value


@dataclass(frozen=True)
class Instance:
    config_root: Path
    state_root: Path
    name: str | None = None

    def __post_init__(self):
        if self.name is not None:
            instance_name(self.name)

    @property
    def config(self):
        return self.config_root / 'instances' / self.name if self.name else self.config_root

    @property
    def state(self):
        return self.state_root / 'instances' / self.name if self.name else self.state_root

    @property
    def unit(self):
        return f'rdpguard-proxy@{self.name}.service' if self.name else 'rdpguard-proxy.service'

    @property
    def label(self):
        return self.name or 'default'


def inventory(config_root, state_root):
    from .proxy_agent import load_config
    from .proxy_setup import regular_read, SetupError
    names = set()
    for root in (config_root, state_root):
        directory = root / 'instances'
        if directory.is_symlink():
            raise SetupError('Каталог экземпляров не может быть ссылкой')
        if directory.exists():
            for path in directory.iterdir():
                if path.name.startswith('.'):
                    continue  # Atomic, uncommitted enrollment directories.
                instance_name(path.name)
                if not path.is_dir() or path.is_symlink():
                    raise SetupError('Необычный объект в каталоге экземпляров')
                names.add(path.name)
    if len(names) > MAX_INSTANCES:
        raise SetupError('Превышен предел числа экземпляров')
    result = []
    for name in (None, *sorted(names)):
        item = Instance(config_root, state_root, name)
        config_path, state_path = item.config / 'config.json', item.state / 'setup-state.json'
        config = load_config(json.loads(regular_read(config_path))) if config_path.exists() else None
        state = json.loads(regular_read(state_path)) if state_path.exists() else {}
        if config is not None or state:
            result.append((item, config, state))
    return result


def validate_available(item, stream, listener, api_port, stream_id):
    from .proxy_setup import SetupError
    entries = inventory(item.config_root, item.state_root)
    if len([cfg for _, cfg, _ in entries if cfg]) >= MAX_INSTANCES:
        raise SetupError('Достигнут предел 32 узла; новый экземпляр не создан')
    for other, cfg, state in entries:
        if other == item and (cfg or state.get('logging_active')):
            raise SetupError('Этот узел уже настроен; используйте другое имя или status/doctor')
        if not cfg:
            continue
        if cfg['stream_id'] == stream_id:
            raise SetupError('Идентификатор stream уже используется другим узлом')
        if (cfg['listener_ip'], cfg['listener_port']) == (listener, stream.container_port):
            raise SetupError('Этот входной IP/порт уже защищается узлом ' + other.label)
        if (cfg['backend_ip'], cfg['backend_port']) == (stream.backend_ip, stream.backend_port):
            raise SetupError('Этот backend уже привязан к узлу ' + other.label)
        if (cfg['api_host'], cfg['api_port']) == (listener, api_port):
            raise SetupError('HTTPS-порт уже закреплён за узлом ' + other.label)


def next_api_port(item, listener, reserved_ports=()):
    used = set(reserved_ports)
    used.update(cfg['api_port'] for _, cfg, _ in inventory(item.config_root, item.state_root)
                if cfg and cfg['api_host'] == listener)
    return next(port for port in range(9443, 65536) if port not in used)


def logging_backup(item, state):
    """Validate recovery material before sharing or removing a managed include."""
    from .proxy_setup import regular_read, SetupError, BLOCK
    backup = Path(state['backup_dir'])
    if '..' in backup.parts or not backup.is_absolute() or not backup.is_relative_to(item.state_root):
        raise SetupError('Backup должен находиться в каталоге состояния агента')
    metadata = json.loads(regular_read(backup / 'metadata.json'))
    path = Path(metadata['path'])
    original = regular_read(backup / 'server_stream_tcp.conf.original') if metadata['existed'] else None
    if hashlib.sha256(original or b'').hexdigest() != metadata['sha256']:
        raise SetupError('Контрольная сумма исходного include не совпадает')
    applied = (original or b'') + (b'\n' if original and not original.endswith(b'\n') else b'') + BLOCK
    identity = state['container_id']
    if not re.fullmatch(r'[a-f0-9]{64}', identity):
        raise SetupError('Некорректная identity контейнера')
    return backup, metadata, path, original, applied, identity


def logging_users(item, path, *, exclude_self=False):
    result = []
    for other, _, state in inventory(item.config_root, item.state_root):
        if state.get('logging_active') is not True or (exclude_self and other == item):
            continue
        recovery = logging_backup(other, state)
        if recovery[2] == path:
            result.append((other, state, recovery))
    return result


def acquire_logging(item, stream, backup_dir, runner):
    from .proxy_setup import apply_info_logging, save_setup_state, regular_read, SetupError
    path = stream.data_path / 'nginx/custom/server_stream_tcp.conf'
    users = logging_users(item, path, exclude_self=True)
    if users:
        _, _, first = users[0]
        if any(recovery[0] != first[0] or recovery[5] != stream.container_id
               for _, _, recovery in users) or regular_read(path) != first[4]:
            raise SetupError('Общий INFO include или контейнер изменён; сначала восстановите существующие узлы')
        save_setup_state(directory=item.state, logging_active=True, status='awaiting_windows',
                         backup_dir=str(first[0]), container_id=stream.container_id)
        return  # No reload, append or new rotation owner when sharing an existing log.
    apply_info_logging(stream, backup_dir, runner, before_change=lambda:
        save_setup_state(directory=item.state, logging_active=True, status='awaiting_windows',
                         backup_dir=str(backup_dir), container_id=stream.container_id))


def release_logging(item, runner):
    from .proxy_setup import regular_read, SetupError, IncludeChange, save_setup_state
    from types import SimpleNamespace
    state = json.loads(regular_read(item.state / 'setup-state.json'))
    _, metadata, path, original, applied, identity = logging_backup(item, state)
    users = logging_users(item, path, exclude_self=True)
    current = regular_read(path) if path.exists() else None
    if users:
        if current != applied or any(recovery[4] != applied or recovery[5] != identity
                                     for _, _, recovery in users):
            raise SetupError('Общий include изменён; остальные узлы используют этот журнал')
    elif current == applied:
        IncludeChange(SimpleNamespace(container_id=identity), path, original, applied, runner,
                      metadata.get('mode', 0o644), metadata.get('owner')).rollback()
    elif current == original:
        runner(['docker', 'exec', identity, 'nginx', '-t'])
        runner(['docker', 'exec', identity, 'nginx', '-s', 'reload'])
    else:
        raise SetupError('Include изменён после установки: автоматическое восстановление запрещено')
    save_setup_state(directory=item.state, logging_active=False, status='unconfigured')
    return bool(users)


def rotate_logs(config_root, state_root, runner):
    """Exactly one logrotate state per shared log, including pre-multi installations."""
    from .proxy_setup import SetupError, regular_read
    owners = {}
    for item, cfg, state in inventory(config_root, state_root):
        if not cfg or state.get('logging_active') is False:
            continue
        rotation = item.config / 'logrotate.conf'
        if not rotation.exists():
            continue
        text = regular_read(rotation)
        log = cfg['nginx_log']
        if log in owners and owners[log][1] != text:
            raise SetupError('Несогласованные настройки ротации одного INFO-журнала')
        owners.setdefault(log, (item, text, rotation))
    legacy_log = None
    legacy = config_root / 'config.json'
    if legacy.exists():
        legacy_log = json.loads(regular_read(legacy))['nginx_log']
    for log, (_, _, rotation) in owners.items():
        name = ('logrotate.status' if log == legacy_log else
                'logrotate-' + hashlib.sha256(log.encode()).hexdigest()[:24] + '.status')
        runner(['/usr/sbin/logrotate', '--state', str(state_root / name), str(rotation)])


@contextmanager
def management_lock(path=Path('/run/rdpguard-proxy-management.lock')):
    import fcntl
    from .proxy_setup import SetupError
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SetupError('Другой мастер или ротация уже выполняется; повторите после завершения') from None
        yield
    finally:
        os.close(fd)
