import re
from urllib.parse import urlsplit

# One DNS label. Underscores stay allowed because the domain regex already
# accepts them. URL characters (: / ? # @) cannot appear in a label.
_LABEL = r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?'
_HOST = re.compile(rf'(?:{_LABEL}\.)*{_LABEL}')
_TOKEN = re.compile(r'[A-Za-z0-9_-]{1,128}')


def ascii_dns_hostname(value: str) -> str:
    """Return the lowercase ASCII hostname, or raise ValueError.

    The value has to be a single hostname. Characters that would change
    the host, port, or path of a URL are rejected, including ones that
    IDNA leaves untouched.
    """
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError('not a dns hostname')
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        raise ValueError('not a dns hostname')
    try:
        ascii_name = value.lower().encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('not a dns hostname') from exc
    if len(ascii_name) > 253 or not _HOST.fullmatch(ascii_name):
        raise ValueError('not a dns hostname')
    return ascii_name


def http01_challenge_url(domain: str, token: str) -> str:
    """Build the HTTP-01 URL without letting the identifier pick the target."""
    host = ascii_dns_hostname(domain)
    if not _TOKEN.fullmatch(token):
        raise ValueError('invalid challenge token')
    path = f'/.well-known/acme-challenge/{token}'
    url = f'http://{host}:80{path}'
    parts = urlsplit(url)
    if parts.hostname != host or parts.port != 80 or parts.path != path or parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError('challenge url escaped the hostname')
    return url
