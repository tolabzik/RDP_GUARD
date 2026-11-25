#!/usr/bin/env python3
"""Build an Ubuntu 24.04 amd64 package with private, preinstalled Python dependencies."""
import argparse
import email
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def wheel_version(path):
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith('.dist-info/METADATA')]
        if len(names) != 1:
            raise ValueError('Expected one application wheel metadata record')
        metadata = email.message_from_bytes(archive.read(names[0]))
        if metadata['Name'].replace('_', '-').lower() != 'rdp-guard':
            raise ValueError('Expected the rdp-guard application wheel')
        version = metadata['Version']
        if not re.fullmatch(r'\d+\.\d+\.\d+(?:\.dev\d+|rc\d+)?', version):
            raise ValueError('Unsupported package version')
        return version.replace('.dev', '~dev').replace('rc', '~rc')


def package_filename(version):
    # GitHub Releases rewrites '~' in uploaded asset names. Keep the Debian
    # version inside control, but use a portable name for downloads/checksums.
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:~(?:dev|rc)\d+)?', version):
        raise ValueError('Unsupported Debian package version')
    portable_version = version.replace('~dev', '-dev.').replace('~rc', '-rc.')
    return f'rdpguard-proxy_{portable_version}_amd64.deb'


def stage_package(root, wheel, *, runner=subprocess.run, wheelhouse=None):
    version = wheel_version(wheel)
    library = root / 'usr/lib/rdpguard-proxy'
    library.mkdir(parents=True)
    args = [sys.executable, '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check',
            '--no-compile', '--only-binary=:all:', '--target', str(library)]
    if wheelhouse is not None:
        args += ['--no-index', '--find-links', str(wheelhouse)]
    runner([*args, str(wheel)], check=True)
    shutil.rmtree(library / 'bin', ignore_errors=True)
    for source in (ROOT / 'deploy/debian').rglob('*'):
        if source.is_file():
            target = root / source.relative_to(ROOT / 'deploy/debian')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    control = root / 'DEBIAN/control'
    control.parent.mkdir(parents=True, exist_ok=True)
    control.write_text(f'''Package: rdpguard-proxy
Version: {version}
Architecture: amd64
Maintainer: RDP Guard project
Section: admin
Priority: optional
Depends: python3.12, nftables, iproute2, openssl, ca-certificates, systemd, logrotate
Suggests: docker.io
Description: RDP Guard nginx stream evidence agent (experimental)
 Includes private Python dependencies. Does not configure nginx, start the agent,
 or enable blocking during package installation. Run rdpguard-proxy setup explicitly.
''')
    docs = root / 'usr/share/doc/rdpguard-proxy'
    docs.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / 'docs/PROXY_SETUP.md', docs / 'PROXY_SETUP.md')
    shutil.copy2(ROOT / 'docs/PROXY_MULTI_INSTANCE.md', docs / 'PROXY_MULTI_INSTANCE.md')
    for file in (root / 'DEBIAN').iterdir():
        os.chmod(file, 0o755 if file.name != 'control' else 0o644)
    return version


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', required=True, type=Path)
    parser.add_argument('--wheelhouse', type=Path)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist/deb')
    args = parser.parse_args(argv)
    if sys.platform != 'linux' or platform.machine() not in ('x86_64', 'amd64') or sys.version_info[:2] != (3, 12):
        parser.error('Build on Ubuntu 24.04 amd64 using Python 3.12')
    release = Path('/etc/os-release').read_text()
    if 'ID=ubuntu' not in release or 'VERSION_ID="24.04"' not in release:
        parser.error('Ubuntu 24.04 is the supported package build platform')
    if shutil.which('dpkg-deb') is None:
        parser.error('dpkg-deb is required')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rdpguard-deb-') as temporary:
        stage = Path(temporary) / 'root'
        version = stage_package(stage, args.wheel.resolve(), wheelhouse=args.wheelhouse)
        destination = args.output_dir / package_filename(version)
        if destination.exists():
            parser.error('Output already exists: ' + str(destination))
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(stage), str(destination)], check=True)
    destination.with_suffix(destination.suffix + '.sha256').write_text(
        hashlib.sha256(destination.read_bytes()).hexdigest() + '  ' + destination.name + '\n')
    print(destination)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
