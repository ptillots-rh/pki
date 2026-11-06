# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Persisted-order checks with a stubbed ACME transport; no keys or network."""

import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


class OrderVerificationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.endpoint = 'https://acme.example/acme/directory'
        logs = self.root / 'logs'
        logs.mkdir()
        self.log = logs / 'letsencrypt.log'
        self.log.write_text('Order URL: https://acme.example/acme/order/123\n')
        account = self.root / 'config/accounts/test-account'
        account.mkdir(parents=True)
        (account / 'private_key.json').write_text('{}')
        (account / 'regr.json').write_text('{}')
        self.network = Mock()
        self.network.get.return_value.json.return_value = {'newNonce': 'https://acme.example/acme/new-nonce'}
        acme = types.ModuleType('acme')
        acme.client = types.SimpleNamespace(ClientNetwork=Mock(return_value=self.network))
        acme.messages = types.SimpleNamespace(RegistrationResource=types.SimpleNamespace(from_json=Mock()))
        josepy = types.ModuleType('josepy')
        josepy.JWK = types.SimpleNamespace(from_json=Mock())
        self.transport = acme.client.ClientNetwork
        spec = importlib.util.spec_from_file_location('verify_order', Path(__file__).with_name('verify-order.py'))
        self.module = importlib.util.module_from_spec(spec)
        with patch.dict('sys.modules', {'acme': acme, 'josepy': josepy}):
            spec.loader.exec_module(self.module)

    def verify(self, order, status, error=None):
        self.network.post.return_value.json.return_value = order
        self.module.verify(self.root, self.endpoint, status, error)

    def test_valid_order_requires_certificate_and_uses_advertised_nonce(self):
        order = {'status': 'valid', 'certificate': 'https://acme.example/acme/cert/1'}
        self.verify(order, 'valid')
        self.network.post.assert_called_once_with('https://acme.example/acme/order/123', None,
                                                 new_nonce_url='https://acme.example/acme/new-nonce')
        self.assertEqual(order, json.loads((self.root / 'verified-order.json').read_text()))
        with self.assertRaises(ValueError):
            self.verify({'status': 'valid'}, 'valid')

    def test_invalid_order_requires_matching_error_and_no_certificate(self):
        for problem in ({'type': 'urn:ietf:params:acme:error:caa'},
                        json.dumps({'type': 'urn:ietf:params:acme:error:caa'})):
            self.verify({'status': 'invalid', 'error': problem}, 'invalid', 'caa')
        for order in ({'status': 'invalid', 'error': {'type': 'urn:ietf:params:acme:error:dns'}},
                      {'status': 'invalid', 'error': {'type': 'urn:ietf:params:acme:error:caa'}, 'certificate': 'unexpected'},
                      {'status': 'processing'}):
            with self.assertRaises(ValueError):
                self.verify(order, 'invalid', 'caa')

    def test_foreign_origin_or_finalize_url_cannot_receive_signed_requests(self):
        for url in ('https://other.example/acme/order/123', 'http://acme.example/acme/order/123',
                    'https://acme.example/acme/order/123/finalize'):
            self.log.write_text(url + '\n')
            with self.assertRaises(ValueError):
                self.verify({}, 'valid')
        self.transport.assert_not_called()

    def test_ambiguous_orders_or_accounts_are_rejected(self):
        self.log.write_text('https://acme.example/acme/order/123\nhttps://acme.example/acme/order/456\n')
        with self.assertRaises(ValueError):
            self.verify({}, 'valid')
        self.log.write_text('https://acme.example/acme/order/123\n')
        other = self.root / 'config/accounts/other'
        other.mkdir()
        (other / 'private_key.json').write_text('{}')
        with self.assertRaises(ValueError):
            self.verify({}, 'valid')
        self.transport.assert_not_called()
