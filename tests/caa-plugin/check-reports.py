#!/usr/bin/env python3
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Fail CI when a required CAA suite is absent, empty, failed or skipped."""

import argparse
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
PREFIX = 'org.dogtagpki.acme.'
SUITES = {
    'unit': {
        'acme': ['caa.CAAContractsTest', 'caa.CAADNSClientLoaderTest',
                 'caa.CAAIssuanceGateTest', 'caa.CAAIssuanceTest', 'caa.CAALookupBudgetTest'],
        'dnsjava': ['caa.dnsjava.DNSJavaCAAProviderTest'],
        'libunbound': ['caa.libunbound.LibUnboundCAAProviderTest',
                      'caa.libunbound.UnboundCAAResponseTest'],
    },
    'dnssec': {'dnssec': ['caa.CAADNSSECIntegrationTest']},
    'operational': {'operational': ['caa.CAAOperationalTest']},
    'engine': {'engine': ['server.ACMEEngineCAATest']},
}


def check(selection):
    total = 0
    for module, suites in SUITES[selection].items():
        base = ROOT / ('base/acme' if module == 'engine' else f'tests/caa-plugin/{module}')
        for suite in suites:
            report = base / 'target/surefire-reports' / f'TEST-{PREFIX}{suite}.xml'
            result = ET.parse(report).getroot()
            tests = int(result.attrib['tests'])
            if tests < 1 or any(int(result.attrib.get(key, 0)) for key in ('failures', 'errors', 'skipped')):
                raise SystemExit(f'Required suite did not pass completely: {report}')
            print(f'{suite}: {tests} passed')
            total += tests
    print(f'{selection}: {total} tests passed, no skips')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('selection', choices=SUITES)
    check(parser.parse_args().selection)
