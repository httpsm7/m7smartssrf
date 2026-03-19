"""
Open Redirect Chain Engine - Follow redirect chains to detect SSRF
"""

import asyncio


class RedirectChainEngine:
    def __init__(self, config):
        self.config = config
        self.max_chain = 5

    async def follow(self, finding):
        """Follow redirect chain and return analysis"""
        chain = []
        url = finding.get('redirect', '')
        visited = set()

        for _ in range(self.max_chain):
            if not url or url in visited:
                break
            visited.add(url)
            chain.append(url)

            # Check if redirect leads to internal
            if any(internal in url for internal in ['127.0.0.1', 'localhost', '169.254', '::1']):
                finding['severity'] = 'HIGH'
                finding['evidence'] += f' | Redirect chain to internal: {url}'
                break

            # Would follow redirect here in full implementation
            break

        return chain
