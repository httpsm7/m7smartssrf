"""
Request Engine - Async HTTP with retry, proxy rotation, UA rotation
"""

import asyncio
import random
import time
import urllib.request
import urllib.error
import urllib.parse
import ssl
import socket
from http.client import HTTPResponse
from io import BytesIO


USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'curl/7.88.1',
    'python-requests/2.31.0',
    'Go-http-client/1.1',
    'Wget/1.21.3',
]


class FakeResponse:
    """Fallback response object"""
    def __init__(self, status=0, body=b'', headers=None, url='', elapsed=0.0, error=None):
        self.status = status
        self.body = body
        self.text = body.decode('utf-8', errors='replace') if body else ''
        self.headers = headers or {}
        self.url = url
        self.elapsed = elapsed
        self.error = error
        self.redirect_url = None


class RequestEngine:
    def __init__(self, config):
        self.config = config
        self._proxy_index = 0

    def _get_proxy(self):
        if self.config.proxy_list:
            p = self.config.proxy_list[self._proxy_index % len(self.config.proxy_list)]
            self._proxy_index += 1
            return p
        return self.config.proxy

    def _get_ua(self):
        if self.config.rotate_ua:
            return random.choice(USER_AGENTS)
        return USER_AGENTS[0]

    def _build_headers(self, extra=None):
        headers = {
            'User-Agent': self._get_ua(),
            'Accept': '*/*',
            'Connection': 'close',
        }
        if self.config.cookies:
            cookie_str = '; '.join(f'{k}={v}' for k, v in self.config.cookies.items())
            headers['Cookie'] = cookie_str
        if self.config.custom_headers:
            headers.update(self.config.custom_headers)
        if extra:
            headers.update(extra)
        return headers

    async def get(self, url, headers=None, retries=None):
        return await self._request('GET', url, headers=headers, retries=retries)

    async def post(self, url, data=None, headers=None, retries=None):
        return await self._request('POST', url, data=data, headers=headers, retries=retries)

    async def _request(self, method, url, data=None, headers=None, retries=None):
        max_retries = retries if retries is not None else self.config.retries
        timeout = self.config.timeout
        all_headers = self._build_headers(headers)

        for attempt in range(max_retries + 1):
            try:
                start = time.time()
                resp = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, self._sync_request, method, url, all_headers, data, timeout
                    ),
                    timeout=timeout + 2
                )
                resp.elapsed = time.time() - start
                return resp
            except asyncio.TimeoutError:
                if attempt == max_retries:
                    return FakeResponse(status=0, url=url, error='timeout', elapsed=timeout)
                await asyncio.sleep(0.5 * (attempt + 1))
            except Exception as e:
                if attempt == max_retries:
                    return FakeResponse(status=0, url=url, error=str(e))
                await asyncio.sleep(0.3)

        return FakeResponse(status=0, url=url, error='max_retries')

    def _sync_request(self, method, url, headers, data, timeout):
        proxy = self._get_proxy()

        # Build opener
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        handlers = [urllib.request.HTTPSHandler(context=ctx)]

        if proxy:
            proxy_handler = urllib.request.ProxyHandler({
                'http': proxy, 'https': proxy
            })
            handlers.insert(0, proxy_handler)

        opener = urllib.request.build_opener(*handlers)
        opener.addheaders = []  # clear defaults

        # Build request
        req_data = None
        if data:
            req_data = urllib.parse.urlencode(data).encode()

        req = urllib.request.Request(url, data=req_data, method=method)
        for k, v in headers.items():
            req.add_header(k, str(v))

        try:
            resp = opener.open(req, timeout=timeout)
            body = resp.read(65536)  # max 64KB
            resp_headers = dict(resp.headers)
            final_url = resp.geturl()
            status = resp.status

            fr = FakeResponse(
                status=status,
                body=body,
                headers=resp_headers,
                url=final_url
            )
            if final_url != url:
                fr.redirect_url = final_url
            return fr

        except urllib.error.HTTPError as e:
            body = b''
            try:
                body = e.read(4096)
            except Exception:
                pass
            return FakeResponse(status=e.code, body=body, url=url, error=str(e))
        except urllib.error.URLError as e:
            return FakeResponse(status=0, url=url, error=str(e.reason))
        except socket.timeout:
            return FakeResponse(status=0, url=url, error='timeout')
        except Exception as e:
            return FakeResponse(status=0, url=url, error=str(e))
