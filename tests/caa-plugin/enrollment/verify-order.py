#!/usr/bin/env python3
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Use the test client's account to fetch and verify the persisted ACME order."""

import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlparse

from acme import client, messages
from josepy import JWK


def verify(directory, endpoint, expected, error=None):
    endpoint_url = urlparse(endpoint)
    base = endpoint_url.path.removesuffix('/directory')
    candidates = []
    log = (directory / 'logs/letsencrypt.log').read_text()
    for token in re.findall(r'https?://[^\s\'"<>]+', log):
        parsed = urlparse(token)
        # Never send an account-signed request to another origin found in a log.
        if ((parsed.scheme, parsed.netloc) == (endpoint_url.scheme, endpoint_url.netloc)
                and re.fullmatch(re.escape(base) + r'/order/[A-Za-z0-9_-]+', parsed.path)
                and not parsed.query and not parsed.fragment):
            candidates.append(token)
    urls = set(candidates)
    if len(urls) != 1:
        raise ValueError(f'Expected one order URL in client log, found {len(urls)}')
    keys = list((directory / 'config/accounts').rglob('private_key.json'))
    if len(keys) != 1:
        raise ValueError('Expected one isolated ACME test account')
    key = JWK.from_json(json.loads(keys[0].read_text()))
    account = messages.RegistrationResource.from_json(json.loads(keys[0].with_name('regr.json').read_text()))
    network = client.ClientNetwork(key, account=account, verify_ssl=True)
    nonce_url = network.get(endpoint).json()['newNonce']
    order = network.post(urls.pop(), None, new_nonce_url=nonce_url).json()
    if order.get('status') != expected:
        raise ValueError(f'Unexpected persisted order status: {order.get("status")}')
    if expected == 'invalid':
        problem = order.get('error')
        # Dogtag currently stores its problem document as a JSON string.
        if isinstance(problem, str):
            problem = json.loads(problem)
        if not isinstance(problem, dict) or problem.get('type') != f'urn:ietf:params:acme:error:{error}':
            raise ValueError('Persisted order does not contain the expected ACME error')
        if order.get('certificate'):
            raise ValueError('Rejected order unexpectedly has a certificate URL')
    elif not order.get('certificate'):
        raise ValueError('Valid order is missing its certificate URL')
    (directory / 'verified-order.json').write_text(json.dumps(order, indent=2) + '\n')
    print(f'PASS: persisted order is {expected}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('endpoint')
    parser.add_argument('expected', choices=['valid', 'invalid'])
    parser.add_argument('--error', choices=['caa', 'dns'])
    args = parser.parse_args()
    verify(args.directory, args.endpoint, args.expected, args.error)
