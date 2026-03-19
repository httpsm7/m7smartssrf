"""
Parameter Extractor - Extract params from URLs
"""

from urllib.parse import urlparse, parse_qs


class ParamExtractor:
    def extract(self, url):
        params = []
        try:
            parsed = urlparse(url)
            if parsed.query:
                for key in parse_qs(parsed.query, keep_blank_values=True).keys():
                    params.append(key)
        except Exception:
            pass
        return params
