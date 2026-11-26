"""Rediscover a managed NPM stream by its complete approved scope, never by PID alone."""
import json
from pathlib import Path
import time

from .proxy_setup import discover_streams, run_command, regular_read, SetupError


def managed(config):
    if "recover_npm" in config:
        return config["recover_npm"] is True
    # Existing .deb enrollments can recover without reissuing their certificates.
    try:
        state = json.loads(regular_read(Path(config["state_file"]).parent / "setup-state.json"))
        return (state.get("schema") == "rdpguard.proxy-setup.v1" and state.get("status") == "paired"
                and state.get("windows_acknowledged") is True)
    except (OSError, ValueError, KeyError, SetupError):
        return False


def select_stream(config, streams):
    # A wildcard Docker publication is valid, but still bound to the exact approved port.
    selected = [s for s in streams if s.backend_ip == config["backend_ip"]
                and s.backend_port == config["backend_port"] and s.container_port == config["listener_port"]
                and str(s.data_path / "logs/rdpguard-stream-info.log") == config["nginx_log"]
                and f"npm-{s.config_path.stem}-{s.container_port}" == config["stream_id"]
                and any(host in (config["listener_ip"], "0.0.0.0") and port == config["listener_port"]
                        for host, port in s.bindings)]
    if len(selected) != 1:
        raise SetupError("Ожидание NPM: не найден единственный stream с прежними портом, backend и каталогом данных")
    return selected[0]


class NpmRecovery:
    def __init__(self, config, runner=run_command):
        self.config, self.runner = config, runner
        self.last_ntp_request = float("-inf")

    def __call__(self):
        synced = self.runner(["timedatectl", "show", "--property=NTPSynchronized", "--value"]).strip()
        if synced != "yes":
            if time.monotonic() - self.last_ntp_request >= 300:
                self.last_ntp_request = time.monotonic()
                self.runner(["timedatectl", "set-ntp", "true"])
            raise SetupError("Ожидание синхронизации времени Linux (NTP)")
        stream = select_stream(self.config, discover_streams(self.runner))
        return dict(self.config, nginx_pid_namespace=stream.namespace,
                    nginx_utc_offset_minutes=stream.utc_offset_minutes)
