# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Test dependency provenance checks without PNC access or invoking Maven."""

import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pnc_dnsjava


class PNCDNSJavaTest(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'dnsjava.jar'
        self.content = b'pinned artifact'
        self.checksum = hashlib.sha256(self.content).hexdigest()

    def test_cached_matching_input_needs_no_network(self):
        self.path.write_bytes(self.content)
        with patch.object(pnc_dnsjava.urllib.request, 'urlopen') as download:
            pnc_dnsjava.prepare_artifact(self.path, 'https://unused', self.checksum, True)
            download.assert_not_called()

    def test_cached_wrong_input_is_rejected_without_fallback(self):
        self.path.write_bytes(b'other artifact with same version')
        with patch.object(pnc_dnsjava.urllib.request, 'urlopen') as download:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                pnc_dnsjava.prepare_artifact(self.path, 'https://unused', self.checksum, False)
            download.assert_not_called()

    def test_missing_offline_input_is_rejected(self):
        with patch.object(pnc_dnsjava.urllib.request, 'urlopen') as download:
            with self.assertRaisesRegex(ValueError, 'not cached'):
                pnc_dnsjava.prepare_artifact(self.path, 'https://unused', self.checksum, True)
            download.assert_not_called()

    def test_download_is_verified_before_it_is_cached(self):
        with patch.object(pnc_dnsjava.urllib.request, 'urlopen',
                          return_value=io.BytesIO(self.content)):
            pnc_dnsjava.prepare_artifact(self.path, 'https://unused', self.checksum, False)
        self.assertEqual(self.path.read_bytes(), self.content)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_bad_download_is_not_cached(self):
        with patch.object(pnc_dnsjava.urllib.request, 'urlopen',
                          return_value=io.BytesIO(b'wrong content')):
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                pnc_dnsjava.prepare_artifact(self.path, 'https://unused', self.checksum, False)
        self.assertEqual(list(self.path.parent.iterdir()), [])

    def test_oversized_download_is_not_cached(self):
        with patch.object(pnc_dnsjava, 'MAX_DOWNLOAD_BYTES', 2), \
                patch.object(pnc_dnsjava.urllib.request, 'urlopen',
                             return_value=io.BytesIO(self.content)):
            with self.assertRaisesRegex(ValueError, 'download limit'):
                pnc_dnsjava.prepare_artifact(self.path, 'https://unused', self.checksum, False)
        self.assertEqual(list(self.path.parent.iterdir()), [])

    def test_repository_override_cannot_select_another_cached_artifact(self):
        for arguments in (['-Dmaven.repo.local=/other'], ['-D', 'maven.repo.local=/other']):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(ValueError, 'Use --cache-dir'):
                    pnc_dnsjava.reject_repository_override(arguments)

    def test_download_failure_prevents_maven_execution(self):
        with patch.object(pnc_dnsjava.urllib.request, 'urlopen',
                          side_effect=OSError('PNC unavailable')), \
                patch.object(pnc_dnsjava.subprocess, 'run') as maven:
            with self.assertRaisesRegex(OSError, 'PNC unavailable'):
                pnc_dnsjava.run(Path(self.directory.name), ['test'])
            maven.assert_not_called()
        self.assertEqual(list((self.path.parent / 'inputs').iterdir()), [])

    def seed_repository(self):
        cache = Path(self.directory.name)
        for directory in (cache / 'inputs',
                          cache / 'repository/dnsjava/dnsjava' / pnc_dnsjava.VERSION):
            directory.mkdir(parents=True)
            for extension in ('jar', 'pom'):
                (directory / ('dnsjava-' + pnc_dnsjava.VERSION + '.' + extension)).write_bytes(
                    self.content)
        return cache

    def test_ready_offline_build_uses_the_isolated_repository(self):
        cache = self.seed_repository()
        with patch.object(pnc_dnsjava, 'CHECKSUMS',
                          {'jar': self.checksum, 'pom': self.checksum}), \
                patch.object(pnc_dnsjava.urllib.request, 'urlopen') as download, \
                patch.object(pnc_dnsjava.subprocess, 'run') as maven:
            pnc_dnsjava.run(cache, ['-f', 'tests/pom.xml', 'test'], offline=True)
            download.assert_not_called()
            maven.assert_called_once_with([
                'mvn', '-B', '-Dmaven.repo.local=' + str(cache / 'repository'),
                '-o', '-f', 'tests/pom.xml', 'test'], check=True)

    def test_wrong_installed_artifact_blocks_the_build(self):
        cache = self.seed_repository()
        jar = cache / 'repository/dnsjava/dnsjava' / pnc_dnsjava.VERSION / (
            'dnsjava-' + pnc_dnsjava.VERSION + '.jar')
        jar.write_bytes(b'Central copy')
        with patch.object(pnc_dnsjava, 'CHECKSUMS',
                          {'jar': self.checksum, 'pom': self.checksum}), \
                patch.object(pnc_dnsjava.subprocess, 'run') as maven:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                pnc_dnsjava.run(cache, ['test'])
            maven.assert_not_called()


if __name__ == '__main__':
    unittest.main()
