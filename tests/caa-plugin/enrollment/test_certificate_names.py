# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Test the enrollment harness's final-certificate identity checks.

Small real X.509 certificates exercise exact DNS SAN comparison, CN membership
and wildcard preservation. This catches profile-induced name changes in issued
output; it is a test assertion after signing, not a CA enforcement control.
"""

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

spec = importlib.util.spec_from_file_location(
    'certificate_names', Path(__file__).with_name('verify_certificate_names.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CertificateNamesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = ec.generate_private_key(ec.SECP256R1())

    def certificate(self, names, cn=None):
        subject = x509.Name([] if cn is None else [x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.now(timezone.utc)
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(self.key.public_key()).serial_number(1)
                .not_valid_before(now).not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .sign(self.key, hashes.SHA256()))

    def test_multiple_names_allow_cn_from_any_checked_san(self):
        names = ['www.example.com', 'api.example.com']
        for cn in (None, *names):
            module.verify_names(self.certificate([x509.DNSName(n) for n in names], cn), names)

    def test_dns_name_case_and_order_do_not_change_identity(self):
        module.verify_names(self.certificate([x509.DNSName('API.example.com'),
                                             x509.DNSName('www.example.com')]),
                            ['WWW.example.com', 'api.example.com'])

    def test_added_and_missing_sans_are_rejected(self):
        for actual in (['www.example.com'], ['www.example.com', 'api.example.com', 'other.example.com']):
            with self.assertRaises(ValueError):
                module.verify_names(self.certificate([x509.DNSName(n) for n in actual]),
                                    ['www.example.com', 'api.example.com'])

    def test_unchecked_cn_is_rejected(self):
        with self.assertRaises(ValueError):
            module.verify_names(self.certificate([x509.DNSName('www.example.com')], 'other.example.com'),
                                ['www.example.com'])

    def test_wildcard_status_cannot_change(self):
        module.verify_names(self.certificate([x509.DNSName('*.example.com')]), ['*.example.com'])
        for actual, expected in [('*.example.com', 'example.com'), ('example.com', '*.example.com')]:
            with self.assertRaises(ValueError):
                module.verify_names(self.certificate([x509.DNSName(actual)]), [expected])

    def test_other_san_types_cannot_pass_as_extra_identifiers(self):
        with self.assertRaises(ValueError):
            module.verify_names(self.certificate([x509.DNSName('www.example.com'),
                                                 x509.UniformResourceIdentifier('https://example.com')]),
                                ['www.example.com'])

    def test_empty_expected_names_are_rejected(self):
        with self.assertRaises(ValueError):
            module.verify_names(self.certificate([x509.DNSName('www.example.com')]), [])


if __name__ == '__main__':
    unittest.main()
