# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Test the private DNS fixture's enrollment scenario inputs without DNS tools.

The signer boundary is replaced so these tests can inspect the zone data used
for multi-name enrollment on any unit-test host. They verify grant selection
and input rejection, not DNSSEC cryptography. The opt-in Java suite runs the
real signer, BIND and Unbound against the same generator.
"""

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


GENERATOR = Path(__file__).resolve().parents[1] / 'src/test/resources/dnssec_fixture.py'
spec = importlib.util.spec_from_file_location('dnssec_fixture', GENERATOR)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class DNSSECFixtureTest(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='caa-fixture-inputs-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    @staticmethod
    def signing_tool(*args, cwd):
        """Preserve signer inputs as output; no validation is claimed here."""
        if args[0] == 'dnssec-keygen':
            return 'fixture-key-' + args[-1]
        if args[0] == 'dnssec-dsfromkey':
            return '; fixture DS placeholder'
        if args[0] == 'dnssec-signzone':
            shutil.copyfile(args[-1], args[args.index('-f') + 1])
            return ''
        raise AssertionError('Unexpected fixture tool: ' + args[0])

    def test_every_requested_name_receives_an_issuer_grant(self):
        with patch.object(fixture, 'run', side_effect=self.signing_tool):
            fixture.prepare(self.root, 'pki.example.com', 'secure-allow', ['api.example.com'])

        zone = (self.root / 'example.zone').read_text()
        self.assertIn('pki.example.com. IN CAA 0 issue "ca.example.com"', zone)
        self.assertIn('api.example.com. IN CAA 0 issue "ca.example.com"', zone)
        self.assertEqual(2, zone.count(' IN CAA '))

    def test_one_name_denial_leaves_no_additive_allow_grant_for_that_name(self):
        # Either the primary or additional SAN may be the denied identity.
        # A leftover allow grant would make the denial scenario ineffective.
        for denied in ('pki.example.com', 'api.example.com'):
            with self.subTest(denied=denied):
                with patch.object(fixture, 'run', side_effect=self.signing_tool):
                    fixture.prepare(self.root, 'pki.example.com', 'secure-allow',
                                    ['api.example.com'], denied)

                records = [line for line in (self.root / 'example.zone').read_text().splitlines()
                           if line.startswith(denied + '. IN CAA ')]
                self.assertEqual([f'{denied}. IN CAA 0 issue "other-ca.example.com"'], records)
                self.assertEqual(1, (self.root / 'example.zone').read_text().count('"ca.example.com"'))

    def test_multiple_names_preserve_each_dnssec_scenario(self):
        """Extra SANs must retain the selected signature and delegation behavior."""
        for scenario in ('secure-deny', 'bogus', 'insecure', 'alias-negative'):
            with self.subTest(scenario=scenario):
                directory = self.root / scenario
                with patch.object(fixture, 'run', side_effect=self.signing_tool):
                    fixture.prepare(directory, 'pki.example.com', scenario, ['api.example.com'])

                child = directory / ('example.unsigned' if scenario == 'insecure' else 'example.signed')
                records = child.read_text()
                issuer = 'other-ca.example.com' if scenario == 'secure-deny' else 'ca.example.com'
                self.assertIn(f'api.example.com. IN CAA 0 issue "{issuer}"', records)

                if scenario == 'bogus':
                    # The signer saw deny data; the served zone was changed
                    # afterward. Actual validation of that corruption is tested
                    # with real BIND/Unbound in the opt-in integration suite.
                    unsigned = (directory / 'example.zone').read_text()
                    self.assertEqual(2, unsigned.count('"other-ca.example.com"'))
                    self.assertNotIn('"other-ca.example.com"', records)
                elif scenario == 'insecure':
                    self.assertFalse((directory / 'example.signed').exists())
                elif scenario == 'alias-negative':
                    self.assertIn('pki.example.com. IN CNAME target.branch.example.com.', records)
                    self.assertIn('branch IN CAA 0 issue "other-ca.example.com"', records)

    def test_invalid_scenario_names_are_rejected_before_running_tools(self):
        cases = [
            ('secure-allow', ['outside.example.net'], None),
            ('secure-allow', ['api.example.com'], 'unrequested.example.com'),
            ('secure-deny', ['api.example.com'], 'api.example.com'),
        ]
        for scenario, names, denied in cases:
            with self.subTest(scenario=scenario, names=names, denied=denied):
                with patch.object(fixture, 'run') as tools:
                    with self.assertRaises(ValueError):
                        fixture.prepare(self.root, 'pki.example.com', scenario, names, denied)
                    tools.assert_not_called()


if __name__ == '__main__':
    unittest.main()
