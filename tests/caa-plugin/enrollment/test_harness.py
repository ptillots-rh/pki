#!/usr/bin/env python3
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check ACME test cleanup and rejection handling without services or root."""

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
            ['bash', '-euc', 'SCRIPT_DIR=unused\npython3() { return 0; }\n' + program], text=True, capture_output=True,
            env={**os.environ, 'INSTANCE': 'pki-tomcat', 'DIRECTORY': 'https://acme.example/acme/directory', 'TEST_ROOT': str(self.root), **settings}, timeout=10)

    def test_cleanup_restores_policy_on_success_and_failure(self):
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

    def test_dnssec_anchor_is_removed_after_policy_restoration(self):
        (self.root / 'caa.conf.original').write_text('enabled=false\n')
        anchor = self.root / 'fixture-anchor'
        anchor.write_text('private test anchor\n')
        program = function('cleanup') + r'''
RUN_DIR="$TEST_ROOT"
CAA_CONFIG="$TEST_ROOT/caa.conf"
TRUST_ANCHOR="$TEST_ROOT/fixture-anchor"
CONFIG_CHANGED=true
systemctl() { test -f "$TRUST_ANCHOR"; }
wait_for_acme() { return 0; }
stop_dns() { :; }
trap cleanup EXIT
exit 0
'''
        result = self.run_shell(program)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(anchor.exists())

    def test_rejection_requires_expected_acme_error_and_no_certificate(self):
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


if __name__ == '__main__':
    unittest.main()
