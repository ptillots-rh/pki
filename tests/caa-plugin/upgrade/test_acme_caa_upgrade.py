# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""CAA migration tests with isolated files and a stubbed upgrade framework."""

import importlib.util
from pathlib import Path
import shutil
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'base/server/upgrade/11.10.1/01-AddACMECAAConfig.py'
TEMPLATE = ROOT / 'base/acme/conf/caa.conf'


class ACMECAAUpgradeTest(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='caa-upgrade-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.template = self.root / 'share/acme/conf/caa.conf'
        self.template.parent.mkdir(parents=True)
        shutil.copyfile(TEMPLATE, self.template)
        self.destination = self.root / 'instance/acme/caa.conf'
        self.destination.parent.mkdir(parents=True)

        # Only the framework boundary is stubbed. Exercise the shipped migration
        # and template against real files without requiring installed PKI modules.
        pki = types.ModuleType('pki')
        pki.server = types.ModuleType('pki.server')
        pki.server.PKIServer = types.SimpleNamespace(SHARE_DIR=str(self.root / 'share'))
        pki.server.upgrade = types.ModuleType('pki.server.upgrade')
        pki.server.upgrade.PKIServerUpgradeScriptlet = type('Scriptlet', (), {})
        spec = importlib.util.spec_from_file_location('add_acme_caa_config', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        with patch.dict('sys.modules', {'pki': pki, 'pki.server': pki.server,
                                       'pki.server.upgrade': pki.server.upgrade}):
            spec.loader.exec_module(module)
        self.migration = module.AddACMECAAConfig()
        self.migration.backup = Mock()
        self.instance = types.SimpleNamespace(copyfile=Mock(side_effect=shutil.copyfile))
        self.subsystem = types.SimpleNamespace(name='acme', caa_conf=str(self.destination))

    def upgrade(self):
        self.migration.upgrade_subsystem(self.instance, self.subsystem)

    def test_missing_configuration_uses_default_off_template_and_instance_copy(self):
        self.upgrade()
        self.assertEqual(self.template.read_bytes(), self.destination.read_bytes())
        settings = dict(line.split('=', 1) for line in self.destination.read_text().splitlines()
                        if line and not line.startswith('#'))
        self.assertEqual({'enabled': 'false'}, settings)
        self.migration.backup.assert_called_once_with(str(self.destination))
        # The real instance helper supplies standard ownership and permissions.
        self.instance.copyfile.assert_called_once_with(str(self.template), str(self.destination))

    def test_existing_enabled_or_disabled_policy_is_preserved(self):
        for enabled in ('true', 'false'):
            with self.subTest(enabled=enabled):
                content = f'# Administrator policy\nenabled={enabled}\nissuerIdentifiers=ca.example.com\n'
                self.destination.write_text(content)
                self.destination.chmod(0o600)
                self.upgrade()
                self.assertEqual(content, self.destination.read_text())
                self.assertEqual(0o600, self.destination.stat().st_mode & 0o777)
        self.migration.backup.assert_not_called()
        self.instance.copyfile.assert_not_called()

    def test_repeated_upgrade_does_not_replace_newly_configured_policy(self):
        self.upgrade()
        self.destination.write_text('enabled=true\n# Configured after migration\n')
        self.upgrade()
        self.assertEqual('enabled=true\n# Configured after migration\n', self.destination.read_text())
        self.assertEqual(1, self.instance.copyfile.call_count)

    def test_non_acme_subsystems_do_not_require_acme_attributes_or_template(self):
        self.template.unlink()
        for name in ('ca', 'kra', 'ocsp', 'est'):
            self.migration.upgrade_subsystem(self.instance, types.SimpleNamespace(name=name))
        self.instance.copyfile.assert_not_called()
        self.migration.backup.assert_not_called()

    def test_existing_symlink_is_not_replaced(self):
        target = self.root / 'administrator.conf'
        target.write_text('enabled=true\n')
        self.destination.symlink_to(target)
        self.upgrade()
        self.assertTrue(self.destination.is_symlink())
        self.assertEqual('enabled=true\n', target.read_text())
        self.instance.copyfile.assert_not_called()

    def test_dangling_symlink_is_not_followed_or_replaced(self):
        self.destination.symlink_to(self.root / 'missing-administrator.conf')
        self.upgrade()
        self.assertTrue(self.destination.is_symlink())
        self.instance.copyfile.assert_not_called()

    def test_missing_template_failure_is_not_hidden(self):
        self.template.unlink()
        with self.assertRaises(FileNotFoundError):
            self.upgrade()
        self.assertFalse(self.destination.exists())

    def test_backup_failure_prevents_writing_configuration(self):
        self.migration.backup.side_effect = OSError('Backup unavailable')
        with self.assertRaises(OSError):
            self.upgrade()
        self.instance.copyfile.assert_not_called()


if __name__ == '__main__':
    unittest.main()
