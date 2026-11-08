from typing import Literal

import pytest
from pydantic import ValidationError


def test_should_parse_prevalidated_domains(testclient):
    from config import AcmeSettings

    settings = AcmeSettings(prevalidated_domains='acc1:Host1.example.org, host2.example.org\n\nacc2:host3.example.org\nacc1:host4.example.org\n')

    assert settings.prevalidated_domains == {
        'acc1': frozenset({'host1.example.org', 'host2.example.org', 'host4.example.org'}),
        'acc2': frozenset({'host3.example.org'}),
    }


@pytest.mark.parametrize('value', ['acc1', 'acc1:', ':host1.example.org', 'acc1:host1.example.org\nbroken'])
def test_should_reject_malformed_prevalidated_domains(testclient, value):
    from config import AcmeSettings

    with pytest.raises(ValidationError, match='Invalid entry'):
        AcmeSettings(prevalidated_domains=value)


@pytest.mark.parametrize('field', ['mail_target_regex', 'target_domain_regex'])
def test_should_warn_about_regex_patterns_that_are_not_lowercase(field: Literal['mail_target_regex', 'target_domain_regex'], caplog):
    from config import AcmeSettings

    settings = AcmeSettings(**{field: r'[A-Z]+\.example\.org'})

    assert getattr(settings, field).pattern == r'[A-Z]+\.example\.org'
    assert 'Regex pattern should be lowercase only' in caplog.text


@pytest.mark.parametrize(
    ('pattern', 'expected'),
    [
        (r'[^@]+@example\.org', r'^mailto:[^@]+@example\.org$'),
        (r' ^[^@]+@example\.org$ ', r'^mailto:[^@]+@example\.org$'),
    ],
)
def test_mailto_target_regex_pattern_is_anchored(pattern: str, expected: str):
    from config import AcmeSettings

    settings = AcmeSettings(mail_target_regex=pattern)

    assert settings.mailto_target_regex_pattern.pattern == expected
    assert settings.mailto_target_regex_pattern.fullmatch('mailto:user@example.org')
    assert not settings.mailto_target_regex_pattern.fullmatch('mailto:user@example.org.attacker')


@pytest.mark.parametrize(
    ('pattern', 'expected'),
    [
        (r'[a-z]+\.example\.org', r'^[a-z]+\.example\.org$'),
        (r' ^[a-z]+\.example\.org$ ', r'^[a-z]+\.example\.org$'),
    ],
)
def test_target_domain_regex_pattern_is_anchored(pattern: str, expected: str):
    from config import AcmeSettings

    settings = AcmeSettings(target_domain_regex=pattern)

    assert settings.target_domain_regex_pattern.pattern == expected
    assert settings.target_domain_regex_pattern.fullmatch('host.example.org')
    assert not settings.target_domain_regex_pattern.fullmatch('evilhost.example.org.attacker.net')


def test_should_reject_prevalidated_domains_not_matching_target_domain_regex(testclient):
    from config import AcmeSettings

    # default regex disallows wildcards and domains without a dot
    for domain in ['*.example.org', 'localhost']:
        with pytest.raises(ValidationError, match='does not match acme_target_domain_regex'):
            AcmeSettings(prevalidated_domains=f'acc1:host1.example.org,{domain}')

    with pytest.raises(ValidationError, match='does not match acme_target_domain_regex'):
        AcmeSettings(target_domain_regex=r'[^\*]+\.example\.org', prevalidated_domains='acc1:host1.example.net')


def test_should_default_to_no_ip_subnets(testclient):
    from config import AcmeSettings

    assert AcmeSettings().target_ip_subnets == frozenset()


def test_should_parse_target_ip_subnets(testclient):
    from ipaddress import ip_address

    from config import AcmeSettings

    settings = AcmeSettings(target_ip_subnets='192.168.1.0/24, fd00:db8::/64')

    assert {str(subnet) for subnet in settings.target_ip_subnets} == {'192.168.1.0/24', 'fd00:db8::/64'}
    assert settings.is_ip_allowed(ip_address('192.168.1.5'))
    assert settings.is_ip_allowed(ip_address('fd00:db8::5'))
    assert not settings.is_ip_allowed(ip_address('10.0.0.1'))


@pytest.mark.parametrize('value', ['not-a-subnet', '192.168.1.0/33', 'fd00:db8::/129'])
def test_should_reject_invalid_target_ip_subnets(testclient, value):
    from config import AcmeSettings

    with pytest.raises(ValidationError, match='acme_target_ip_subnets'):
        AcmeSettings(target_ip_subnets=value)


def test_should_reject_prevalidated_ip_not_within_target_ip_subnets(testclient):
    from config import AcmeSettings

    # ip subnets default to empty, so a prevalidated IP is rejected
    with pytest.raises(ValidationError, match='not within acme_target_ip_subnets'):
        AcmeSettings(prevalidated_domains='acc1:192.0.2.1')

    # an IP outside the configured subnets is rejected as well
    with pytest.raises(ValidationError, match='not within acme_target_ip_subnets'):
        AcmeSettings(target_ip_subnets='10.0.0.0/8', prevalidated_domains='acc1:192.0.2.1')


def test_should_accept_prevalidated_ip_identifiers(testclient):
    from config import AcmeSettings

    # ip addresses within the allowed subnets may be prevalidated
    settings = AcmeSettings(target_ip_subnets='192.0.2.0/24, 2001:db8::/32', prevalidated_domains='acc1:192.0.2.1,2001:db8::1')

    assert settings.prevalidated_domains == {'acc1': frozenset({'192.0.2.1', '2001:db8::1'})}


def test_should_accept_prevalidated_domains_matching_custom_target_domain_regex(testclient):
    from config import AcmeSettings

    settings = AcmeSettings(target_domain_regex=r'[^\*]+\.example\.org', prevalidated_domains='acc1:host1.example.org')

    assert settings.prevalidated_domains == {'acc1': frozenset({'host1.example.org'})}


def test_should_match_whole_domain_against_target_domain_regex(testclient):
    from config import AcmeSettings

    with pytest.raises(ValidationError, match='does not match acme_target_domain_regex'):
        AcmeSettings(target_domain_regex=r'host1\.example\.org', prevalidated_domains='acc1:evilhost1.example.org.attacker.net')
