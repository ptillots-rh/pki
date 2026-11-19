# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Test the report checks used to validate the CAA Java test selections.

Synthetic Surefire XML in a temporary directory exercises report preparation,
missing suites and failed or skipped tests without running Maven or DNS tools.
These checks prevent old reports from hiding gaps in the current test run.
"""

from contextlib import redirect_stdout
import importlib.util
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('caa_reports', Path(__file__).with_name('check_reports.py'))
reports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reports)


class ReportTest(unittest.TestCase):
    """Isolate each report check from the workspace's real Maven reports."""

    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.patch = patch.object(reports, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.required = list(reports.reports('unit'))

    def write_reports(self, **attributes):
        """Create one minimal Surefire report for each required unit suite."""
        values = dict(tests='1', failures='0', errors='0', skipped='0')
        values.update(attributes)
        fields = ' '.join(f'{key}="{value}"' for key, value in values.items())
        for _, report in self.required:
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(f'<testsuite {fields}/>')

    def test_prepare_removes_old_required_reports_and_exposes_omitted_suite(self):
        """Delete stale selected reports, preserve others and reject an omitted run."""
        self.write_reports()
        other = self.required[0][1].with_name('TEST-unrelated.xml')
        other.write_text('<testsuite tests="1"/>')

        reports.prepare('unit')
        reports.prepare('unit')

        self.assertTrue(other.exists())
        self.assertTrue(all(not report.exists() for _, report in self.required))
        with self.assertRaises(FileNotFoundError):
            reports.check('unit')

    def test_accepts_complete_reports_created_after_preparation(self):
        """Accept reports written by a complete run after old reports are removed."""
        reports.prepare('unit')
        self.write_reports()
        with redirect_stdout(StringIO()):
            reports.check('unit')

    def test_rejects_empty_failed_errored_or_skipped_suites(self):
        """Require every selected suite to execute with no failures, errors or skips."""
        for values in ({'tests': '0'}, {'failures': '1'}, {'errors': '1'}, {'skipped': '1'}):
            with self.subTest(values=values):
                self.write_reports(**values)
                with self.assertRaises(SystemExit):
                    reports.check('unit')


if __name__ == '__main__':
    unittest.main()
