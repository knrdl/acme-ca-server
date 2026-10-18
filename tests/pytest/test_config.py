import pytest
from pydantic import ValidationError
from typing import Literal


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
def test_should_reject_regex_patterns_that_are_not_lowercase(field: Literal['mail_target_regex', 'target_domain_regex']):
    from config import AcmeSettings

    with pytest.raises(ValidationError, match='pattern must be lowercase only'):
        AcmeSettings(**{field: r'[A-Z]+\.example\.org'})


@pytest.mark.parametrize('field', ['mail_target_regex', 'target_domain_regex'])
def test_should_accept_lowercase_regex_patterns(field: Literal['mail_target_regex', 'target_domain_regex']):
    from config import AcmeSettings

    settings = AcmeSettings(**{field: r'[a-z]+\.example\.org'})

    assert getattr(settings, field).pattern == r'[a-z]+\.example\.org'


def test_should_reject_prevalidated_domains_not_matching_target_domain_regex(testclient):
    from config import AcmeSettings

    # default regex disallows wildcards and domains without a dot
    for domain in ['*.example.org', 'localhost']:
        with pytest.raises(ValidationError, match='does not match acme_target_domain_regex'):
            AcmeSettings(prevalidated_domains=f'acc1:host1.example.org,{domain}')

    with pytest.raises(ValidationError, match='does not match acme_target_domain_regex'):
        AcmeSettings(target_domain_regex=r'[^\*]+\.example\.org', prevalidated_domains='acc1:host1.example.net')


def test_should_accept_prevalidated_domains_matching_custom_target_domain_regex(testclient):
    from config import AcmeSettings

    settings = AcmeSettings(target_domain_regex=r'[^\*]+\.example\.org', prevalidated_domains='acc1:host1.example.org')

    assert settings.prevalidated_domains == {'acc1': frozenset({'host1.example.org'})}


def test_should_match_whole_domain_against_target_domain_regex(testclient):
    from config import AcmeSettings

    with pytest.raises(ValidationError, match='does not match acme_target_domain_regex'):
        AcmeSettings(target_domain_regex=r'host1\.example\.org', prevalidated_domains='acc1:evilhost1.example.org.attacker.net')


def test_should_match_target_domain_regex_case_insensitive(testclient):
    from config import AcmeSettings

    settings = AcmeSettings(target_domain_regex=r'[^\*]+\.Example\.ORG', prevalidated_domains='acc1:host1.example.org')

    assert settings.prevalidated_domains == {'acc1': frozenset({'host1.example.org'})}
