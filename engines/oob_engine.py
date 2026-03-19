"""
OOB Detection Engine - Interactsh integration (no API key needed)
"""

import asyncio
import random
import string
import json
import urllib.request
import ssl
import time


class OOBEngine:
    def __init__(self, config):
        self.config = config
        self.domain = None
        self.correlation_id = None
        self.secret = None
        self.hits = []
        self._payload_map = {}  # payload_id -> task info

        # Public Interactsh servers (no API key needed)
        self.SERVERS = [
            'https://oast.pro',
            'https://oast.me',
            'https://oast.fun',
            'https://oast.site',
            'https://oast.online',
            'interact.sh',
        ]

        self._server = None

    async def setup(self):
        """Register with Interactsh and get callback domain"""
        if self.config.oob_server:
            self.domain = self.config.oob_server
            return self.domain

        # Try to register with interactsh
        for server in self.SERVERS:
            try:
                domain = await asyncio.get_event_loop().run_in_executor(
                    None, self._register, server
                )
                if domain:
                    self.domain = domain
                    self._server = server
                    return domain
            except Exception:
                continue

        # Fallback: use a random subdomain pattern
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        self.domain = f"{rand}.interact.sh"
        return self.domain

    def _register(self, server):
        """Attempt Interactsh registration"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Generate correlation ID
            self.correlation_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
            self.secret = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

            base = server if server.startswith('http') else f'https://{server}'
            url = f"{base}/register"

            payload = json.dumps({
                'public-key': self.secret,
                'secret-key': self.secret,
                'correlation-id': self.correlation_id,
            }).encode()

            req = urllib.request.Request(url, data=payload, method='POST')
            req.add_header('Content-Type', 'application/json')

            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            data = json.loads(resp.read())

            if 'domain' in data:
                return data['domain']
        except Exception:
            pass
        return None

    def get_payloads(self):
        """Generate unique OOB payloads"""
        if not self.domain:
            return []

        payloads = []
        for i in range(5):
            uid = ''.join(random.choices(string.ascii_lowercase, k=8))
            sub = f"{uid}.{self.domain}"
            payloads.extend([
                f'http://{sub}/',
                f'https://{sub}/',
            ])
            self._payload_map[uid] = {'domain': sub}

        return payloads

    async def get_hits(self):
        """Poll Interactsh for callbacks"""
        if not self._server or not self.correlation_id:
            return self.hits

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            base = self._server if self._server.startswith('http') else f'https://{self._server}'
            url = f"{base}/poll?id={self.correlation_id}&secret={self.secret}"

            req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            data = json.loads(resp.read())

            for item in data.get('data', []):
                self.hits.append({
                    'vulnerable': True,
                    'url': item.get('full-id', ''),
                    'type': 'oob_callback',
                    'severity': 'HIGH',
                    'evidence': f"OOB callback received: {item.get('protocol', 'unknown')} from {item.get('remote-address', '')}",
                    'param': 'oob',
                    'payload': self.domain,
                    'task_type': 'oob',
                    'status_code': 0,
                    'response_size': 0,
                    'redirect': None,
                })
        except Exception:
            pass

        return self.hits
