#!/usr/bin/env python3
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare final certificate names with the names checked before enrollment."""

import argparse
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID


def verify_names(certificate, expected_names):
    """Require the final DNS SAN set and every CN to stay within the checked identities."""
    expected = {name.lower() for name in expected_names}
    if not expected:
        raise ValueError('Expected certificate names must not be empty')

    # Exact SAN equality catches both added and omitted names. A matching CN
    # must not hide an extra SAN or an identifier type CAA did not check.
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if any(not isinstance(name, x509.DNSName) for name in san):
        raise ValueError('Final SAN contains an unchecked identifier type')
    actual = {name.lower() for name in san.get_values_for_type(x509.DNSName)}
    if actual != expected:
        raise ValueError(f'Final DNS SANs differ from the checked names: {actual}')
    # A profile may fill an absent CN from an existing SAN, but cannot add a name.
    for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if attribute.value.lower() not in expected:
            raise ValueError('Profile introduced an unchecked common name')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('certificate', type=Path)
    parser.add_argument('names', nargs='+')
    args = parser.parse_args()
    verify_names(x509.load_pem_x509_certificate(args.certificate.read_bytes()), args.names)
    print('PASS: final SANs and CN contain only the checked certificate names')
