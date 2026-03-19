"""
Input Engine - Load, normalize, deduplicate URLs
"""

import os
import re
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs, quote


class InputEngine:
    def __init__(self, config):
        self.config = config

    def load(self, target):
        urls = []

        if not target:
            return urls

        # Single URL
        if target.startswith(('http://', 'https://')):
            urls = [target]
        # File
        elif os.path.isfile(target):
            urls = self._load_file(target)
        else:
            print(f"[!] Target not found: {target}")
            return []

        # Normalize + deduplicate
        normalized = []
        seen = set()
        for url in urls:
            clean = self._normalize(url)
            if clean and clean not in seen:
                seen.add(clean)
                normalized.append(clean)

        return normalized

    def _load_file(self, path):
        urls = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle Burp-style raw request format
                        if line.startswith('GET ') or line.startswith('POST '):
                            url = self._parse_burp_request(line)
                            if url:
                                urls.append(url)
                        elif line.startswith('http'):
                            urls.append(line)
        except Exception as e:
            print(f"[!] File load error: {e}")
        return urls

    def _normalize(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            parsed = urlparse(url)
            if not parsed.netloc:
                return None

            # Normalize scheme
            scheme = parsed.scheme.lower()

            # Normalize host
            host = parsed.netloc.lower()

            # Remove default ports
            host = re.sub(r':80$', '', host) if scheme == 'http' else host
            host = re.sub(r':443$', '', host) if scheme == 'https' else host

            # Normalize path
            path = parsed.path or '/'
            if not path.startswith('/'):
                path = '/' + path

            # Sort query params for dedup
            query = ''
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                sorted_params = sorted(params.items())
                query = urlencode(sorted_params, doseq=True)

            normalized = urlunparse((scheme, host, path, '', query, ''))
            return normalized

        except Exception:
            return None

    def _parse_burp_request(self, line):
        """Basic Burp request format parsing"""
        try:
            parts = line.split()
            if len(parts) >= 3 and parts[2].startswith('HTTP'):
                return parts[1]  # return path, needs host
        except Exception:
            pass
        return None
