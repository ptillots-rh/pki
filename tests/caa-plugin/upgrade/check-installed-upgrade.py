#!/usr/bin/env python3
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify CAA migration and the real upgrade command on a disposable instance.

Temporarily replaces the instance policy and restores it in finally. It does
not reset the upgrade tracker or claim to test an old-to-new RPM transaction.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace

import pki.server
import pki.server.upgrade
import pki.util


def check(name):
    instance = pki.server.PKIServerFactory.create(name)
    instance.load()
    subsystem = instance.get_subsystem('acme')
    if subsystem is None:
        raise ValueError('ACME must already be configured')
    path = Path(subsystem.caa_conf)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Test requires a regular, existing CAA policy file')
    original = path.stat()
    with tempfile.TemporaryDirectory(prefix='caa-installed-upgrade-') as directory:
        backup = Path(directory) / 'original.conf'
        shutil.copy2(path, backup)
        # Isolate the targeted migration's rollback records from instance history.
        owner = SimpleNamespace(logs_dir=directory, makedirs=instance.makedirs, touch=instance.touch)
        upgrader = pki.server.upgrade.PKIServerUpgrader(owner)
        migrations = [s for s in upgrader.scriptlets(pki.util.Version('11.10.1'))
                      if type(s).__name__ == 'AddACMECAAConfig']
        if len(migrations) != 1:
            raise ValueError('Install the proposed CAA upgrade script before testing')
        migration = migrations[0]
        try:
            upgrader.init_scriptlet(migration)
            path.unlink()
            migration.upgrade_subsystem(instance, subsystem)
            active = [line.strip() for line in path.read_text().splitlines()
                      if line.strip() and not line.lstrip().startswith('#')]
            if active != ['enabled=false']:
                raise ValueError('Migration did not preserve default-off behavior')
            info = path.stat()
            if ((info.st_uid, info.st_gid) != (instance.uid, instance.gid)
                    or info.st_mode & 0o777 != pki.server.DEFAULT_FILE_MODE):
                raise ValueError('Migrated ownership or permissions differ from PKI defaults')
            upgrader.revert_scriptlet(migration)
            if path.exists():
                raise ValueError('Rollback did not remove the newly created policy')
            # Exercise preservation through the actual command, including comments.
            content = 'enabled=true\n# Upgrade must preserve administrator policy\n'
            path.write_text(content)
            os.chown(path, instance.uid, instance.gid)
            path.chmod(pki.server.DEFAULT_FILE_MODE)
            subprocess.run(['pki-server', 'upgrade', name], check=True, timeout=120)
            if path.read_text() != content:
                raise ValueError('Upgrade command replaced existing CAA policy')
        finally:
            shutil.copy2(backup, path)
            os.chown(path, original.st_uid, original.st_gid)
    print('PASS: migration, ownership/permissions, rollback and upgrade-command preservation')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('instance')
    check(parser.parse_args().instance)
