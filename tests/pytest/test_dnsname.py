import re

import pytest
from dnsname import ascii_dns_hostname, http01_challenge_url

# The default domain filter, and the README example that is meant to
# allow only one suffix. Both still match the unsafe identifiers below.
DEFAULT_DOMAIN_REGEX = re.compile(r'^[^\*]+\.[^\.]+$')
SUFFIX_REGEX = re.compile(r'^[^\*]+\.mydomain\.org$')


def test_normal_hostname_keeps_the_http01_target():
    assert ascii_dns_hostname('Example.COM') == 'example.com'
    assert ascii_dns_hostname('foo_bar.example.com') == 'foo_bar.example.com'
    assert http01_challenge_url('Example.COM', 'abc_DEF-123') == 'http://example.com:80/.well-known/acme-challenge/abc_DEF-123'


def test_unicode_hostname_is_requested_as_punycode():
    assert ascii_dns_hostname('münchen.example') == 'xn--mnchen-3ya.example'
    assert http01_challenge_url('münchen.example', 'tok') == 'http://xn--mnchen-3ya.example:80/.well-known/acme-challenge/tok'


@pytest.mark.parametrize(
    'value',
    [
        'internal-host:8080/admin?.x',
        'attacker.com/?.mydomain.org',
        'foo.bar:443',
        'a.b/c',
        'example.com.',
        '-bad.example',
        'bad-.example',
        'ex ample.com',
        '',
    ],
)
def test_rejects_identifier_that_is_not_one_hostname(value: str):
    with pytest.raises(ValueError):
        ascii_dns_hostname(value)
    with pytest.raises(ValueError):
        http01_challenge_url(value, 'tok')


def test_default_regex_allows_the_identifiers_that_retarget_the_challenge():
    assert DEFAULT_DOMAIN_REGEX.fullmatch('internal-host:8080/admin?.x')
    assert DEFAULT_DOMAIN_REGEX.fullmatch('foo.bar:443')
    assert SUFFIX_REGEX.fullmatch('attacker.com/?.mydomain.org')


def test_invalid_token_is_rejected():
    with pytest.raises(ValueError):
        http01_challenge_url('example.com', 'tok/en')
