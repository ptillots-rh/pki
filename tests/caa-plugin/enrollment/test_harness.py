#!/usr/bin/env python3
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check enrollment harness control flow without installed ACME or root.

Extracted shell functions run against temporary files and stubbed service/client
commands. These tests qualify preflight checks, restoration, process cleanup and
failure classification; they do not exercise DNSSEC validation or CA issuance.
"""

import fcntl
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'enrollment/test-enrollment.sh'


def function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', SCRIPT.read_text(), re.M | re.S)
    if match is None:
        raise AssertionError('Missing shell function: ' + name)
    return match.group(0) + '\n'


class ACMEFeatureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_shell(self, program, **settings):
        return subprocess.run(
            ['bash', '-euc', 'SCRIPT_DIR=unused\npython3() { return 0; }\n' + program],
            text=True, capture_output=True,
            env={**os.environ, 'INSTANCE': 'pki-tomcat',
                 'DIRECTORY': 'https://acme.example/acme/directory',
                 'TEST_ROOT': str(self.root), **settings},
            timeout=10)

    def run_preflight(self, contents):
        config = self.root / 'engine.conf'
        if contents is not None:
            config.write_text(contents)
        source = Path(__file__).resolve().parents[3] / 'base/common/python'
        env = {**os.environ, 'TEST_ROOT': str(self.root),
               'PYTHONDONTWRITEBYTECODE': '1',
               'PYTHONPATH': str(source) + os.pathsep + os.environ.get('PYTHONPATH', '')}
        result = subprocess.run(
            ['bash', '-euc', function('check_engine_config') +
             'check_engine_config "$TEST_ROOT/engine.conf"'],
            text=True, capture_output=True, env=env, timeout=10)
        if contents is not None:
            self.assertEqual(config.read_text(), contents, 'Preflight must not edit engine.conf')
        else:
            self.assertFalse(config.exists())
        return result

    def test_caa_preflight_accepts_configured_origin_and_context_paths(self):
        for value in ('https://acme.example', 'https://acme.example:18443/acme',
                      'https://[::1]:18443/acme/', 'http://acme.example/acme'):
            with self.subTest(value=value):
                result = self.run_preflight(f'# Public origin\nbaseURL = {value}\n')
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_caa_preflight_requires_an_active_nonempty_base_url(self):
        for contents in ('enabled=true\n', '# baseURL=https://acme.example\n',
                         'baseURL=\n', 'baseURL=https://acme.example\nbaseURL=\n'):
            with self.subTest(contents=contents):
                result = self.run_preflight(contents)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('CAA requires a public HTTP(S) baseURL', result.stderr)
                self.assertIn(str(self.root / 'engine.conf'), result.stderr)

    def test_caa_preflight_rejects_bad_urls_without_printing_the_value(self):
        for value in ('acme.example', 'ftp://acme.example', 'https://',
                      'https://user:secret@acme.example', 'https://acme.example:99999',
                      'https://acme.example:bad', 'https://acme.example/bad path'):
            with self.subTest(value=value):
                result = self.run_preflight(f'baseURL={value}\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('CAA requires', result.stderr)
                self.assertNotIn(value, result.stderr)

    def test_caa_preflight_reports_missing_or_unreadable_properties(self):
        for contents in (None, 'malformed property without delimiter\n'):
            with self.subTest(contents=contents):
                result = self.run_preflight(contents)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Cannot read ACME engine configuration', result.stderr)

    def test_cleanup_restores_policy_on_success_and_failure(self):
        """Preserve both the original policy and exit status, including signal-style failures."""
        config = self.root / 'caa.conf'
        original = self.root / 'caa.conf.original'
        original.write_text('enabled=false\n# original policy\n')
        program = function('cleanup') + r'''
RUN_DIR="$TEST_ROOT"
CAA_CONFIG="$TEST_ROOT/caa.conf"
CONFIG_CHANGED=true
systemctl() { printf 'restart\n' >> "$TEST_ROOT/actions"; }
wait_for_acme() { printf 'ready\n' >> "$TEST_ROOT/actions"; }
stop_dns() { printf 'stop-dns\n' >> "$TEST_ROOT/actions"; }
trap cleanup EXIT
exit "$ORIGINAL_STATUS"
'''
        for status in (0, 1, 130, 143):
            with self.subTest(status=status):
                config.write_text('enabled=true\n# temporary policy\n')
                actions = self.root / 'actions'
                actions.write_text('')
                result = self.run_shell(program, ORIGINAL_STATUS=str(status))
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(config.read_text(), original.read_text())
                self.assertEqual(actions.read_text().splitlines(), ['restart', 'ready', 'stop-dns'])

    def test_failed_restore_restart_cannot_report_success(self):
        (self.root / 'caa.conf.original').write_text('enabled=false\n')
        program = function('cleanup') + r'''
RUN_DIR="$TEST_ROOT"
CAA_CONFIG="$TEST_ROOT/caa.conf"
CONFIG_CHANGED=true
systemctl() { return 7; }
wait_for_acme() { return 0; }
stop_dns() { touch "$TEST_ROOT/dns-stopped"; }
trap cleanup EXIT
exit 0
'''
        result = self.run_shell(program)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Restore/restart failed', result.stderr)
        self.assertTrue((self.root / 'dns-stopped').exists())

    def test_background_service_does_not_keep_the_test_lock(self):
        (self.root / 'caa.conf.original').write_text('enabled=false\n')
        program = function('cleanup') + r'''
RUN_DIR="$TEST_ROOT"
CAA_CONFIG="$TEST_ROOT/caa.conf"
CONFIG_CHANGED=true
exec 9>"$TEST_ROOT/test.lock"
flock -n 9
systemctl() { sleep 2 >/dev/null 2>&1 & }
wait_for_acme() { return 0; }
stop_dns() { :; }
trap cleanup EXIT
exit 0
'''
        result = self.run_shell(program)
        self.assertEqual(result.returncode, 0, result.stderr)
        with (self.root / 'test.lock').open('w') as lock:
            # A service child that inherited descriptor 9 would still hold it.
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_dns_shutdown_is_bounded_when_the_fixture_ignores_term(self):
        program = function('stop_dns') + r'''
bash -c 'trap "" TERM; touch "$TEST_ROOT/ready"; exec sleep 30' &
DNS_PID=$!
for attempt in {1..50}; do
    [[ -f "$TEST_ROOT/ready" ]] && break
    sleep 0.02
done
[[ -f "$TEST_ROOT/ready" ]]
fixture_pid="$DNS_PID"
stop_dns
[[ -z "$DNS_PID" ]]
! kill -0 "$fixture_pid" 2>/dev/null
'''
        result = self.run_shell(program)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dnssec_probe_requires_the_expected_rcode_and_ad_flag(self):
        """
        Readiness must distinguish secure fixture data, expected insecurity and actual SERVFAIL.
        """
        probe = self.root / 'probe.txt'
        program = function('dnssec_response_matches') + r'''
dnssec_response_matches "$TEST_ROOT/probe.txt" "$EXPECTED"
'''
        for rcode, flags, expected, accepted in (
                ('NOERROR', 'qr rd ra ad', 'secure', True),
                ('NOERROR', 'qr rd ra', 'secure', False),
                ('NOERROR', 'qr rd ra', 'insecure', True),
                ('NOERROR', 'qr rd ra ad', 'insecure', False),
                ('SERVFAIL', 'qr rd ra', 'insecure', False),
                ('SERVFAIL', 'qr rd ra', 'bogus', True),
                ('NOERROR', 'qr rd ra', 'bogus', False)):
            with self.subTest(rcode=rcode, flags=flags, expected=expected):
                probe.write_text(f';; ->>HEADER<<- opcode: QUERY, status: {rcode}, id: 1\n'
                                 f';; flags: {flags}; QUERY: 1, ANSWER: 1\n')
                result = self.run_shell(program, EXPECTED=expected)
                self.assertEqual(result.returncode == 0, accepted)
        probe.write_text('')
        self.assertNotEqual(self.run_shell(program, EXPECTED='secure').returncode, 0)

    def test_rejection_requires_expected_acme_error_and_no_certificate(self):
        """A nonzero client exit alone must never count as a successful rejection test."""
        case = self.root / 'caa-deny'
        (case / 'logs').mkdir(parents=True)
        log = case / 'logs/letsencrypt.log'
        program = function('expect_rejection') + r'''
RUN_DIR="$TEST_ROOT"
fail() { echo "$*" >&2; exit 1; }
run_certbot() { return "$CLIENT_STATUS"; }
expect_rejection caa-deny caa
'''
        for status, error, expected in ((1, 'caa', 0), (0, 'caa', 1),
                                         (124, 'caa', 1), (137, 'caa', 1),
                                         (1, 'connection', 1)):
            with self.subTest(status=status, error=error):
                log.write_text('urn:ietf:params:acme:error:' + error)
                result = self.run_shell(program, CLIENT_STATUS=str(status))
                self.assertEqual(result.returncode, expected, result.stderr)
        log.write_text('urn:ietf:params:acme:error:caa')
        cert = case / 'config/live/caa-enrollment-test/cert.pem'
        cert.parent.mkdir(parents=True)
        cert.touch()
        result = self.run_shell(program, CLIENT_STATUS='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unexpectedly produced a certificate', result.stderr)


    def test_caa_runs_all_dnssec_scenarios_and_optional_single_name_denial(self):
        """Keep one complete scenario selection for ordinary and multi-name CAA tests."""
        (self.root / 'caa.conf.original').write_text('enabled=false\n')
        program = function('run_caa_tests') + r'''
RUN_DIR="$TEST_ROOT"
CAA_CONFIG="$TEST_ROOT/caa.conf"
CERTIFICATE_NAMES=(pki.example.com)
if [[ "$MULTIPLE_NAMES" == true ]]; then
    CERTIFICATE_NAMES+=(api.example.com)
fi
start_dnssec() { echo "dns $*"; }
configure_caa() { echo configure; }
expect_success() { echo "allow $1"; }
expect_rejection() { echo "reject $*"; }
stop_dns() { echo stop; }
run_caa_tests
'''
        expected = []
        for scenario in ('secure-allow', 'secure-deny', 'bogus', 'insecure', 'alias-negative'):
            expected.extend([f'dns {scenario}', 'configure'])
            if scenario == 'secure-deny':
                expected.append('reject secure-deny caa')
            elif scenario == 'bogus':
                expected.append('reject bogus dns')
            else:
                expected.append(f'allow {scenario}')

        for multiple in ('false', 'true'):
            with self.subTest(multiple=multiple):
                result = self.run_shell(program, MULTIPLE_NAMES=multiple)
                self.assertEqual(0, result.returncode, result.stderr)
                denial = (['dns secure-allow api.example.com', 'configure',
                           'reject one-name-denied caa'] if multiple == 'true' else [])
                self.assertEqual(expected + denial + ['stop', 'reject dns-unavailable dns'],
                                 result.stdout.splitlines())

    def test_command_line_exposes_one_caa_mode_and_rejects_removed_options(self):
        """Help and invalid options are handled before any installed service is accessed."""
        result = subprocess.run(['bash', str(SCRIPT), '--help'],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('--caa', result.stdout)
        self.assertNotIn('--dnssec', result.stdout)
        self.assertNotIn('--provider', result.stdout)

        for option in ('--dnssec', '--provider'):
            with self.subTest(option=option):
                result = subprocess.run(['bash', str(SCRIPT), option],
                                        text=True, capture_output=True, timeout=10)
                self.assertNotEqual(0, result.returncode)
                self.assertIn('Unknown argument: ' + option, result.stderr)


if __name__ == '__main__':
    unittest.main()
