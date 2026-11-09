#!/usr/bin/env python3
"""Security preflight regressions; run with the deployment's Ansible venv Python."""
import copy
import importlib.util
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
# tests/ansible.py is a stand runner, not the installed Ansible package.
sys.path = [entry for entry in sys.path if Path(entry or '.').resolve() != ROOT / 'tests']


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy/ansible/library' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


tls = load('vless_tls_check')
panel = load('vless_panel')


class LocalModule:
    check_mode = True

    def __init__(self, cert, key, hostname):
        self.params = {'cert_path': str(cert), 'key_path': str(key), 'hostname': hostname}

    def get_bin_path(self, name, required=False):
        return shutil.which(name)

    def run_command(self, argv):
        result = subprocess.run(argv, text=True, capture_output=True)
        return result.returncode, result.stdout, result.stderr


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is required for real certificate fixtures')
class TLSPreflight(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='vless-tls-module-')
        cls.root = Path(cls.directory.name)
        for name, days in [('valid', 3), ('other', 3), ('short', 1)]:
            cls.command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256',
                         '-nodes', '-days', str(days), '-subj', '/CN=ignored.example.com',
                         '-addext', 'subjectAltName=DNS:node.example.com,DNS:*.example.net,IP:127.0.0.1',
                         '-keyout', str(cls.root / (name + '.key')),
                         '-out', str(cls.root / (name + '.crt'))])
            (cls.root / (name + '.key')).chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    @staticmethod
    def command(argv):
        result = subprocess.run(argv, capture_output=True)
        if result.returncode:
            raise RuntimeError('certificate fixture generation failed')

    def fixture(self, cert='valid', key='valid', hostname='node.example.com'):
        return LocalModule(self.root / (cert + '.crt'), self.root / (key + '.key'), hostname)

    def test_valid_pair_is_read_only_in_check_mode(self):
        paths = [self.root / 'valid.crt', self.root / 'valid.key']
        before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
        result = tls.verify(self.fixture())
        self.assertEqual(result['changed'], False)
        self.assertEqual(result['valid'], True)
        self.assertEqual(before, [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths])

    def test_wrong_hostname_rejected_even_when_common_name_matches(self):
        with self.assertRaisesRegex(tls.CertificateError, 'SAN'):
            tls.verify(self.fixture(hostname='ignored.example.com'))

    def test_mismatched_private_key_rejected(self):
        with self.assertRaisesRegex(tls.CertificateError, 'key-pair'):
            tls.verify(self.fixture(key='other'))

    def test_insufficient_remaining_validity_rejected(self):
        with self.assertRaisesRegex(tls.CertificateError, '24 hours'):
            tls.verify(self.fixture(cert='short', key='short'))

    def test_future_certificate_rejected(self):
        with mock.patch.object(tls.time, 'time', return_value=time.time() - 86400):
            with self.assertRaisesRegex(tls.CertificateError, 'not started'):
                tls.verify(self.fixture())

    def test_group_readable_private_key_rejected(self):
        target = self.root / 'group-readable.key'
        shutil.copyfile(self.root / 'valid.key', target)
        target.chmod(0o640)
        with self.assertRaisesRegex(tls.CertificateError, 'permissions'):
            tls.verify(LocalModule(self.root / 'valid.crt', target, 'node.example.com'))

    def test_missing_key_rejected(self):
        with self.assertRaisesRegex(tls.CertificateError, 'exist'):
            tls.verify(self.fixture(key='missing'))

    def test_ip_requires_ip_san_and_wildcard_matches_one_label(self):
        self.assertTrue(tls.verify(self.fixture(hostname='127.0.0.1'))['valid'])
        self.assertTrue(tls.verify(self.fixture(hostname='one.example.net'))['valid'])
        with self.assertRaisesRegex(tls.CertificateError, 'SAN'):
            tls.verify(self.fixture(hostname='two.one.example.net'))
        self.assertFalse(tls.identity_matches({'subjectAltName': [('DNS', '127.0.0.1')]}, '127.0.0.1'))
        self.assertFalse(tls.dns_matches('part*.example.net', 'partial.example.net'))


class PanelPreflight(unittest.TestCase):
    def fixture(self):
        return {'url': 'http://127.0.0.1:2053', 'directory_port': 14443, 'subscription_port': 2096,
                'users': [{'email': 'alice', 'uuid': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                           'sub_id': 'test-subscription', 'exit': 'out-a', 'enabled': True}],
                'ingress_endpoints': [{'address': 'node.example.com', 'port': 443,
                                       'remark': 'in', 'security': 'tls'}]}

    def test_remote_cleartext_and_embedded_credentials_rejected(self):
        for url in ['http://192.0.2.1:2053', 'https://admin:secret@example.com',
                    'https://example.com/?password=secret']:
            with self.subTest(url=url), self.assertRaises(panel.PanelError):
                params = self.fixture()
                params['url'] = url
                panel.validate(params)

    def test_duplicate_uuid_is_case_insensitive(self):
        params = self.fixture()
        second = copy.deepcopy(params['users'][0])
        second.update(email='bob', uuid=second['uuid'].upper())
        params['users'].append(second)
        with self.assertRaisesRegex(panel.PanelError, 'unique'):
            panel.validate(params)

    def test_public_tls_and_sni_are_pinned_in_advertisement(self):
        params = self.fixture()
        params['ingress_endpoints'][0]['tls_server_name'] = 'cert.example.net'
        entry = panel.validate(params)[0]
        self.assertEqual(entry['dest'], 'node.example.com')
        self.assertEqual(entry['forceTls'], 'tls')
        self.assertEqual(entry['sni'], 'cert.example.net')
        params['ingress_endpoints'][0]['security'] = 'none'
        with self.assertRaisesRegex(panel.PanelError, 'TLS'):
            panel.validate(params)


if __name__ == '__main__':
    unittest.main(verbosity=2)
