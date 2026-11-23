#!/usr/bin/env bash
# Provision a new Linux installation from local files. Never starts/enables it.
set -euo pipefail
umask 077
if [[ $# -ne 3 ]]; then
  echo "Usage: $0 /path/rdp_guard.whl /path/bundle/linux /path/linux-wheelhouse" >&2
  exit 2
fi
[[ $(id -u) -eq 0 && $(uname -s) == Linux ]] || { echo 'Run as root on Linux.' >&2; exit 2; }
wheel=$1
bundle=$2
wheelhouse=$3
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
unit="$script_dir/../deploy/rdpguard-proxy.service"
[[ -f "$wheel" && "$wheel" == *.whl && -d "$bundle" && -d "$wheelhouse" && -f "$unit" ]] || {
  echo 'Provide local wheel, Linux bundle, Linux dependency wheelhouse and the shipped service unit.' >&2; exit 2;
}
command -v python3.12 >/dev/null
command -v systemctl >/dev/null
for target in /opt/rdpguard-proxy /etc/rdpguard-proxy /var/lib/rdpguard-proxy /etc/systemd/system/rdpguard-proxy.service; do
  [[ ! -e "$target" && ! -L "$target" ]] || { echo "Refusing existing target: $target" >&2; exit 2; }
done
python3.12 - "$bundle" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
for name in ('config.json', 'ca.pem', 'server.pem', 'server.key'):
    path = root / name
    if not path.is_file() or path.is_symlink():
        raise SystemExit('Expected regular bundle file: ' + name)
cfg = json.loads((root / 'config.json').read_text())
if cfg.get('enforcement_validated') is not False:
    raise SystemExit('Initial installation requires enforcement_validated=false')
for name, expected in {'ca_file': '/etc/rdpguard-proxy/ca.pem',
                       'cert_file': '/etc/rdpguard-proxy/server.pem',
                       'key_file': '/etc/rdpguard-proxy/server.key',
                       'state_file': '/var/lib/rdpguard-proxy/state.sqlite3'}.items():
    if cfg.get(name) != expected:
        raise SystemExit('Unexpected installed path: ' + name)
PY
install -d -m 0755 /opt/rdpguard-proxy
install -d -m 0700 /etc/rdpguard-proxy /var/lib/rdpguard-proxy
python3.12 -m venv /opt/rdpguard-proxy/venv
/opt/rdpguard-proxy/venv/bin/python -m pip install --no-index --find-links "$wheelhouse" --only-binary=:all: "$wheel"
for name in config.json ca.pem server.pem server.key; do
  install -m 0600 "$bundle/$name" "/etc/rdpguard-proxy/$name"
done
/opt/rdpguard-proxy/venv/bin/rdpguard-proxy --config /etc/rdpguard-proxy/config.json --check-config
install -m 0644 "$unit" /etc/systemd/system/rdpguard-proxy.service
systemctl daemon-reload
echo 'Provisioned in monitor mode. Service has NOT been started or enabled.'
echo 'Review docs/PROXY_AGENT.md, certificates, log path and API reachability before systemctl start rdpguard-proxy.'
