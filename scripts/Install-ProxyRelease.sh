#!/usr/bin/env bash
# Download a pinned, checksummed release and run the interactive Linux setup.
# Save this file locally before executing it; do not pipe it into bash.
set -euo pipefail
umask 077

readonly RELEASE_TAG='v1.1.0-rc.3'
readonly PACKAGE_VERSION='1.1.0~rc3'
# GitHub rewrites '~' in uploaded asset names; keep the filename independent of
# the Debian metadata version, which still needs '~' for prerelease ordering.
readonly PACKAGE='rdpguard-proxy_1.1.0-rc.3_amd64.deb'
readonly RELEASE_URL="https://github.com/tolabzik/RDP_GUARD/releases/download/${RELEASE_TAG}"

fail() { printf '%s\n' "$*" >&2; exit 1; }

if [[ ${1:-} == --help && $# -eq 1 ]]; then
  printf 'Usage: sudo bash %s\nDownloads %s for Ubuntu 24.04 amd64, verifies it, installs it, and starts setup.\n' "$0" "$RELEASE_TAG"
  exit 0
fi
[[ $# -eq 0 ]] || fail 'This release installer takes no arguments (except --help).'
[[ $(uname -s) == Linux ]] || fail 'Supported host: Ubuntu 24.04 amd64.'
[[ -r /etc/os-release ]] || fail 'Cannot read /etc/os-release.'
# The OS-owned release file is authoritative; user environment cannot override it.
os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
[[ $os_id == ubuntu && $os_version == 24.04 ]] || fail 'Supported host: Ubuntu 24.04 amd64.'
[[ $(dpkg --print-architecture) == amd64 ]] || fail 'This package requires amd64.'
[[ -t 0 ]] || fail 'Run the downloaded script in a terminal; do not pipe it into bash.'

if [[ $(id -u) != 0 ]]; then
  command -v sudo >/dev/null || fail 'Run this installer as root, or install sudo.'
  exec sudo -- bash "$0"
fi
for program in curl sha256sum dpkg-deb dpkg-query apt-get; do
  command -v "$program" >/dev/null || fail "Required command is missing: $program"
done

installed_version=$(dpkg-query -W -f='${Version}' rdpguard-proxy 2>/dev/null || true)
if [[ -n $installed_version ]] && dpkg --compare-versions "$installed_version" gt "$PACKAGE_VERSION"; then
  fail "A newer package is installed ($installed_version). This helper will not downgrade it."
fi

rdp_release_dir=$(mktemp -d /tmp/rdpguard-release.XXXXXXXX)
cleanup() { rm -rf -- "$rdp_release_dir"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Downloading RDP Guard proxy %s...\n' "$RELEASE_TAG"
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  --retry 3 --connect-timeout 15 --max-time 600 --max-filesize 104857600 \
  "$RELEASE_URL/$PACKAGE" --output "$rdp_release_dir/$PACKAGE"
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  --retry 3 --connect-timeout 15 --max-time 60 --max-filesize 4096 \
  "$RELEASE_URL/$PACKAGE.sha256" --output "$rdp_release_dir/$PACKAGE.sha256"

expected_checksum=''; expected_name=''; extra=''
read -r expected_checksum expected_name extra < "$rdp_release_dir/$PACKAGE.sha256" || true
[[ $(awk 'END { print NR }' "$rdp_release_dir/$PACKAGE.sha256") == 1 &&
   $expected_checksum =~ ^[0-9a-fA-F]{64}$ && $expected_name == "$PACKAGE" && -z $extra ]] ||
  fail 'Release checksum file must contain exactly this package and one SHA256.'
actual_checksum=$(sha256sum "$rdp_release_dir/$PACKAGE" | awk '{ print $1 }')
expected_checksum=$(printf '%s' "$expected_checksum" | tr '[:upper:]' '[:lower:]')
[[ $actual_checksum == "$expected_checksum" ]] || fail 'Package SHA256 mismatch; nothing was installed.'

[[ $(dpkg-deb --field "$rdp_release_dir/$PACKAGE" Package) == rdpguard-proxy &&
   $(dpkg-deb --field "$rdp_release_dir/$PACKAGE" Version) == "$PACKAGE_VERSION" &&
   $(dpkg-deb --field "$rdp_release_dir/$PACKAGE" Architecture) == amd64 ]] ||
  fail 'Package identity, version or architecture does not match this release.'

printf 'Verified %s. Installing system dependencies and package...\n' "$PACKAGE"
apt-get update
apt-get install -y -- "$rdp_release_dir/$PACKAGE"

if [[ -f /etc/rdpguard-proxy/config.json ]] || compgen -G '/etc/rdpguard-proxy/instances/*/config.json' >/dev/null; then
  printf 'Updated; existing proxy configuration was retained.\nRun sudo rdpguard-proxy doctor to check it.\nTo add another Windows: sudo rdpguard-proxy add --instance NAME.\n'
else
  printf 'Starting setup. Keep this terminal open while importing the .rdpg file on Windows.\n'
  /usr/bin/rdpguard-proxy setup
fi
