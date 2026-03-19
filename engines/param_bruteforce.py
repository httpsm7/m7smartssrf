"""
Parameter Bruteforce Engine - 30+ SSRF-prone hidden params with priority scoring
"""


class ParamBruteforce:
    def __init__(self, config):
        self.config = config

        # Priority-scored SSRF params
        self.HIGH_PRIORITY = [
            'url', 'uri', 'redirect', 'redirectUrl', 'redirect_uri',
            'callback', 'callbackUrl', 'callback_url', 'return', 'returnUrl',
            'return_url', 'next', 'dest', 'destination', 'target',
            'link', 'src', 'source', 'host', 'endpoint'
        ]

        self.MEDIUM_PRIORITY = [
            'path', 'file', 'page', 'document', 'folder', 'root',
            'fetch', 'load', 'open', 'read', 'data', 'api',
            'request', 'resource', 'feed', 'image', 'img',
            'proxy', 'forward', 'go', 'jump', 'location'
        ]

        self.LOW_PRIORITY = [
            'ref', 'referer', 'referrer', 'site', 'domain',
            'out', 'view', 'dir', 'show', 'content', 'window',
            'to', 'from', 'href', 'action', 'service'
        ]

    def get_priority_params(self, url):
        if self.config.mode == 'fast':
            return self.HIGH_PRIORITY
        elif self.config.mode == 'deep':
            return self.HIGH_PRIORITY + self.MEDIUM_PRIORITY + self.LOW_PRIORITY
        else:
            return self.HIGH_PRIORITY + self.MEDIUM_PRIORITY
