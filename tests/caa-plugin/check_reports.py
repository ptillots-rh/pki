#!/usr/bin/env python3
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Fail validation when a required CAA suite is absent, empty, failed or skipped."""

import argparse
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
PREFIX = 'org.dogtagpki.acme.'
# Required suites for each independently checked test selection.
SUITES = {
    'unit': {
        'base/acme': [
            'caa.CAAContractsTest',
            'caa.CAADNSClientLoaderTest',
            'caa.CAAIssuanceGateTest',
            'caa.DefaultCAAValidatorTest',
            'caa.CAALookupBudgetTest',
            'server.ACMEEngineCAATest',
            'server.ACMEOrderServletCAATest',
        ],
        'base/acme/caa-plugins/dnsjava': ['caa.dnsjava.DNSJavaCAAProviderTest'],
    },
    'dnssec': {'tests/caa-plugin': ['caa.CAADNSSECIntegrationTest']},
    'operational': {'tests/caa-plugin': ['caa.CAAOperationalTest']},
}


def reports(selection):
    """Locate each required Surefire report for the selected test group."""
    for module, suites in SUITES[selection].items():
        for suite in suites:
            report = ROOT / module / 'target/surefire-reports' / f'TEST-{PREFIX}{suite}.xml'
            yield suite, report


def prepare(selection):
    """Remove required reports before Maven so an omitted suite cannot reuse one."""
    for _, report in reports(selection):
        report.unlink(missing_ok=True)


def check(selection):
    """Require every selected suite to have run successfully without skips."""
    total = 0
    for suite, report in reports(selection):
        result = ET.parse(report).getroot()
        tests = int(result.attrib['tests'])
        if tests < 1 or any(int(result.attrib.get(key, 0))
                            for key in ('failures', 'errors', 'skipped')):
            raise SystemExit(f'Required suite did not pass completely: {report}')
        print(f'{suite}: {tests} passed')
        total += tests
    print(f'{selection}: {total} tests passed, no skips')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('selection', choices=SUITES)
    parser.add_argument('--prepare', action='store_true',
                        help='Remove required reports before running Maven')
    args = parser.parse_args()
    if args.prepare:
        prepare(args.selection)
    else:
        check(args.selection)
