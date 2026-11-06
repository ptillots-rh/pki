#!/usr/bin/env python3
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run Maven with the exact dnsjava artifact from the recorded PNC build."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request


BUILD_ID = 'BSHSPFWQYXIAA'
VERSION = '3.6.5'
REPOSITORY = (
    'https://gateway.indy.corp.redhat.com/api/content/maven/hosted/'
    'lightwell-upstream-builds/dnsjava/dnsjava/' + VERSION
)
CHECKSUMS = {
    'jar': '4720cb6acebc9179d16ddd2b1134a236c42799c3240cb353c9b5094b147a56ca',
    'pom': 'd50ea6f20e29a98f9571ff421c2f7154b24133e92848ce4bb5a6f11aa44e815c',
}
MAX_DOWNLOAD_BYTES = 4 * 1024 * 1024


def verify(path, checksum):
    """Reject different binaries even when their Maven coordinates match."""
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != checksum:
        raise ValueError('PNC checksum mismatch: ' + str(path))


def prepare_artifact(path, url, checksum, offline):
    """Cache verified inputs; never fall back to another artifact repository."""
    if path.exists():
        verify(path, checksum)
        return
    if offline:
        raise ValueError('PNC input is not cached; run online first: ' + str(path))

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            with urllib.request.urlopen(url, timeout=30) as response:
                size = 0
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_DOWNLOAD_BYTES:
                        raise ValueError('PNC input exceeds download limit: ' + url)
                    output.write(chunk)
        verify(temporary, checksum)
        temporary.replace(path)
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def reject_repository_override(arguments):
    """Keep Maven from accidentally selecting the normal Central cache."""
    for argument in arguments:
        if 'maven.repo.local' in argument:
            raise ValueError('Use --cache-dir instead of overriding maven.repo.local')


def run(cache, arguments, offline=False):
    reject_repository_override(arguments)
    offline = offline or '-o' in arguments or '--offline' in arguments
    cache = cache.expanduser().resolve()
    repository = cache / 'repository'
    inputs = cache / 'inputs'
    installed = repository / 'dnsjava' / 'dnsjava' / VERSION

    for extension, checksum in CHECKSUMS.items():
        filename = 'dnsjava-' + VERSION + '.' + extension
        prepare_artifact(inputs / filename, REPOSITORY + '/' + filename,
                         checksum, offline)

    # Use the real POM so transitive dependency information is retained.
    ready = all((installed / ('dnsjava-' + VERSION + '.' + ext)).is_file()
                for ext in CHECKSUMS)
    if ready:
        for extension, checksum in CHECKSUMS.items():
            verify(installed / ('dnsjava-' + VERSION + '.' + extension), checksum)
    else:
        command = ['mvn', '-B', '-N', '-Dmaven.repo.local=' + str(repository)]
        if offline:
            command.append('-o')
        command.extend([
            'org.apache.maven.plugins:maven-install-plugin:3.2.0:install-file',
            '-Dfile=' + str(inputs / ('dnsjava-' + VERSION + '.jar')),
            '-DpomFile=' + str(inputs / ('dnsjava-' + VERSION + '.pom')),
            '-Dpackaging=jar',
        ])
        subprocess.run(command, cwd=cache, check=True)
        for extension, checksum in CHECKSUMS.items():
            verify(installed / ('dnsjava-' + VERSION + '.' + extension), checksum)

    print('Using dnsjava ' + VERSION + ' from PNC build ' + BUILD_ID, flush=True)
    command = ['mvn', '-B', '-Dmaven.repo.local=' + str(repository)]
    if offline and '-o' not in arguments and '--offline' not in arguments:
        command.append('-o')
    subprocess.run(command + arguments, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache-dir', type=Path,
                        default=Path.home() / '.m2' / 'pnc-dnsjava' / BUILD_ID,
                        help='Separate cache for the pinned PNC inputs and Maven repository')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('maven_arguments', nargs=argparse.REMAINDER,
                        help='Maven arguments after --')
    options = parser.parse_args()
    arguments = options.maven_arguments
    if arguments[:1] == ['--']:
        arguments = arguments[1:]
    if not arguments:
        parser.error('Specify a Maven build after --')
    try:
        run(options.cache_dir, arguments, options.offline)
    except (OSError, ValueError) as error:
        print('Unable to use PNC dnsjava: ' + str(error), file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        return error.returncode
    return 0


if __name__ == '__main__':
    sys.exit(main())
