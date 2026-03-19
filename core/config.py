"""
Config module - handles all configuration including YAML config file
"""

import os
import yaml
from pathlib import Path


class Config:
    def __init__(self, args=None):
        self.threads = 20
        self.timeout = 10
        self.retries = 2
        self.delay = 0
        self.proxy = None
        self.proxy_list = []
        self.mode = 'fast'
        self.oob = False
        self.oob_server = None
        self.bypass = None
        self.protocols = None
        self.headers_only = False
        self.params_only = False
        self.custom_payloads = None
        self.output = 'report'
        self.format = 'all'
        self.resume = None
        self.save_session = False
        self.cookies = {}
        self.custom_headers = {}
        self.auth_token = None
        self.safe = False
        self.stealth_delay = False
        self.rotate_ua = False
        self.verbose = False
        self.silent = False
        self.target = None

        if args:
            self._load_from_args(args)

    def _load_from_args(self, args):
        if hasattr(args, 'config') and args.config:
            self._load_yaml(args.config)

        # Override with CLI args
        for attr in ['threads', 'timeout', 'retries', 'delay', 'proxy',
                     'mode', 'oob', 'oob_server', 'bypass', 'output', 'format',
                     'resume', 'safe', 'verbose', 'silent', 'target']:
            if hasattr(args, attr) and getattr(args, attr) is not None:
                setattr(self, attr, getattr(args, attr))

        if hasattr(args, 'headers_only'):
            self.headers_only = args.headers_only
        if hasattr(args, 'params_only'):
            self.params_only = args.params_only
        if hasattr(args, 'stealth_delay'):
            self.stealth_delay = args.stealth_delay
        if hasattr(args, 'rotate_ua'):
            self.rotate_ua = args.rotate_ua
        if hasattr(args, 'save_session'):
            self.save_session = args.save_session
        if hasattr(args, 'payloads') and args.payloads:
            self.custom_payloads = args.payloads

        # Parse cookies
        if hasattr(args, 'cookies') and args.cookies:
            self.cookies = self._parse_cookies(args.cookies)

        # Parse custom headers
        if hasattr(args, 'headers') and args.headers:
            self.custom_headers = self._parse_headers_str(args.headers)

        # Auth token
        if hasattr(args, 'auth') and args.auth:
            self.auth_token = args.auth
            self.custom_headers['Authorization'] = f'Bearer {args.auth}'

        # Proxy list
        if hasattr(args, 'proxy_list') and args.proxy_list:
            self._load_proxy_list(args.proxy_list)

        # Protocols
        if hasattr(args, 'protocols') and args.protocols:
            self.protocols = [p.strip() for p in args.protocols.split(',')]

        # Mode adjustments
        self._apply_mode_defaults()

    def _apply_mode_defaults(self):
        if self.mode == 'fast':
            if self.threads == 20:
                self.threads = 30
        elif self.mode == 'deep':
            if self.threads == 20:
                self.threads = 10
            self.retries = 3
        elif self.mode == 'stealth':
            if self.threads == 20:
                self.threads = 5
            self.stealth_delay = True
            self.rotate_ua = True
            if self.delay == 0:
                self.delay = 1.5

    def _load_yaml(self, path):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            for k, v in data.items():
                if hasattr(self, k):
                    setattr(self, k, v)
        except Exception as e:
            print(f"[!] Config load error: {e}")

    def _parse_cookies(self, cookie_str):
        cookies = {}
        for part in cookie_str.split(';'):
            if '=' in part:
                k, v = part.strip().split('=', 1)
                cookies[k.strip()] = v.strip()
        return cookies

    def _parse_headers_str(self, headers_str):
        headers = {}
        for part in headers_str.split(','):
            if ':' in part:
                k, v = part.strip().split(':', 1)
                headers[k.strip()] = v.strip()
        return headers

    def _load_proxy_list(self, path):
        try:
            with open(path) as f:
                self.proxy_list = [line.strip() for line in f if line.strip()]
        except Exception:
            pass
