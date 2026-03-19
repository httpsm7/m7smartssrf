"""
Response Analyzer - Detect SSRF via status, size, keywords, timing
False positive reduction via multi-confirmation
"""

import re
import time


# Keywords indicating successful internal access
POSITIVE_KEYWORDS = [
    # Linux/system
    r'root:.*:0:0',          # /etc/passwd
    r'daemon:.*:/sbin',
    r'nobody:.*:/nonexistent',
    r'\[boot loader\]',      # Windows boot.ini
    r'for 16-bit app',       # win.ini
    # Cloud metadata
    r'ami-[0-9a-f]{8,}',     # AWS AMI ID
    r'"accountId"\s*:',       # AWS metadata JSON
    r'"instanceId"\s*:',
    r'"privateIpAddress"',
    r'iam/security-credentials',
    r'"computeMetadata"',     # GCP
    r'"instance"\s*:\s*\{',  # Azure/GCP
    r'metadata\.google\.internal',
    # Redis
    r'\+PONG',
    r'\$\d+\r\nredis_version',
    r'redis_version',
    # Internal services
    r'Apache.*Server',
    r'nginx/\d+\.\d+',
    r'<title>.*admin.*</title>',
    r'dashboard',
    r'internal server error',
    # Open redirect indicators
    r'Location:\s*http',
]

# False positive keywords (common in normal responses)
FALSE_POSITIVE_KEYWORDS = [
    'not found',
    'invalid url',
    'bad request',
    'access denied',
    'forbidden',
    'parameter missing',
]

COMPILED_POS = [re.compile(p, re.I | re.DOTALL) for p in POSITIVE_KEYWORDS]
COMPILED_NEG = [re.compile(p, re.I) for p in FALSE_POSITIVE_KEYWORDS]


class ResponseAnalyzer:
    def __init__(self, config):
        self.config = config
        self._baselines = {}  # url -> (status, size, elapsed)

    def set_baseline(self, url, resp):
        self._baselines[url] = (resp.status, len(resp.body), resp.elapsed)

    def analyze(self, response, task):
        if response is None or response.status == 0:
            # Check for timeout-based blind SSRF
            if response and response.error == 'timeout':
                baseline = self._baselines.get(task['url'])
                if baseline and baseline[2] < self.config.timeout * 0.8:
                    return self._build_result(task, response, 'blind_timeout', 'MEDIUM',
                                              'Time-based blind SSRF detected (timeout differential)')
            return None

        body = response.text or ''
        status = response.status
        size = len(response.body)

        # Check for positive keyword matches
        for pattern in COMPILED_POS:
            if pattern.search(body):
                matched = pattern.pattern
                # Check false positive
                if not self._is_false_positive(body):
                    severity = self._calc_severity(task, matched)
                    return self._build_result(task, response, 'internal', severity,
                                              f'Keyword match: {matched[:50]}')

        # Status-based detection (compare to baseline)
        baseline = self._baselines.get(task['url'])
        if baseline:
            b_status, b_size, b_elapsed = baseline
            # Status code changed significantly
            if b_status in [400, 404, 200] and status == 200 and b_size != size:
                size_diff = abs(size - b_size)
                if size_diff > 200:  # significant size change
                    return self._build_result(task, response, 'blind_size', 'LOW',
                                              f'Response size differential: {size_diff} bytes')

        # Redirect-based detection
        if status in [301, 302, 303, 307, 308] and response.redirect_url:
            redir = response.redirect_url
            if any(internal in redir for internal in ['127.0.0.1', 'localhost', '169.254']):
                return self._build_result(task, response, 'redirect', 'HIGH',
                                          f'Redirect to internal: {redir}')

        # OOB marker check (if OOB payload used)
        payload = task.get('payload', '')
        if 'interactsh' in payload and status in [200, 301, 302]:
            return self._build_result(task, response, 'oob_candidate', 'MEDIUM',
                                      'OOB payload sent - check callback server')

        return None

    def _is_false_positive(self, body):
        body_lower = body.lower()
        return any(fp in body_lower for fp in FALSE_POSITIVE_KEYWORDS[:3])

    def _calc_severity(self, task, matched_pattern):
        high_patterns = ['root:.*:0:0', 'ami-', 'iam/security-credentials',
                         'accountId', 'privateIpAddress', 'PONG', 'redis_version']
        for hp in high_patterns:
            if hp.lower() in matched_pattern.lower():
                return 'HIGH'
        payload = task.get('payload', '')
        if '169.254.169.254' in payload:
            return 'HIGH'
        if '127.0.0.1' in payload or 'localhost' in payload:
            return 'MEDIUM'
        return 'LOW'

    def _build_result(self, task, response, vuln_type, severity, evidence):
        return {
            'vulnerable': True,
            'url': task.get('url', ''),
            'param': task.get('param', ''),
            'payload': task.get('payload', ''),
            'type': vuln_type,
            'severity': severity,
            'evidence': evidence,
            'status_code': response.status if response else 0,
            'response_size': len(response.body) if response else 0,
            'redirect': response.redirect_url if response else None,
            'task_type': task.get('type', 'unknown'),
        }
