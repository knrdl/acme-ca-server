import pytest


def test_should_ignore_duplicated_domains(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {
            'identifiers': [
                {'type': 'dns', 'value': 'host1.example.org'},
                {'type': 'dns', 'value': 'host1.example.org'},
                {'type': 'dns', 'value': 'host2.example.org'},
            ]
        },
        account_id,
    )

    assert response.json()['status'] == 'pending', response.json()
    assert len(response.json()['authorizations']) == 2, response.json()


def test_should_reflect_order_on_create(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {
            'identifiers': [
                {'type': 'dns', 'value': 'host1.example.org'},
                {'type': 'dns', 'value': 'host1.example.org'},
                {'type': 'dns', 'value': 'host2.example.org'},
            ]
        },
        account_id,
    )

    new_order_data = response.json()

    order_url = response.headers['Location']

    response = signed_request(order_url, response.headers['Replay-Nonce'], '', account_id)
    view_order_data = response.json()

    assert view_order_data == new_order_data


def test_should_handle_unknown_orders(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {
            'identifiers': [
                {'type': 'dns', 'value': 'host1.example.org'},
            ]
        },
        account_id,
    )

    order_url = response.headers['Location']

    response = signed_request(order_url + '123', response.headers['Replay-Nonce'], '', account_id)
    assert response.status_code == 404
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:malformed'

    view_order_err = response.json()

    response = signed_request(order_url + '123/finalize', response.headers['Replay-Nonce'], {'csr': 'DEADBEEF'}, account_id)
    assert response.status_code == 404
    assert response.json() == view_order_err


def test_should_prevalidate_whitelisted_domains(signed_request, directory, caplog):
    import logging

    from config import settings

    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': ['mailto:admin@example.org']})
    account_id = response.headers['Location']
    thumbprint = signed_request.account_jwk.thumbprint()
    settings.acme.prevalidated_domains = {thumbprint: frozenset({'host1.example.org'})}
    try:
        caplog.set_level(logging.INFO, logger='uvicorn')
        response = signed_request(
            directory['newOrder'],
            response.headers['Replay-Nonce'],
            {'identifiers': [{'type': 'dns', 'value': 'Host1.example.org'}]},
            account_id,
        )
        assert response.json()['status'] == 'ready', response.json()
        assert 'mail address: admin@example.org' in caplog.text, caplog.text
        assert 'prevalidated domains: host1.example.org)' in caplog.text.lower(), caplog.text

        caplog.clear()
        response = signed_request(
            directory['newOrder'],
            response.headers['Replay-Nonce'],
            {'identifiers': [{'type': 'dns', 'value': 'host1.example.org'}, {'type': 'dns', 'value': 'host2.example.org'}]},
            account_id,
        )
        assert 'prevalidated domains: host1.example.org)' in caplog.text, caplog.text
        assert response.json()['status'] == 'pending', response.json()
        statuses = []
        for authz_url in response.json()['authorizations']:
            response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
            statuses.append((response.json()['identifier']['value'], response.json()['status']))
        assert sorted(statuses) == [('host1.example.org', 'valid'), ('host2.example.org', 'pending')], statuses
    finally:
        settings.acme.prevalidated_domains = {}


def test_should_lowercase_domains(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {
            'identifiers': [
                {'type': 'dns', 'value': 'Host1.Example.ORG'},
                {'type': 'dns', 'value': 'host1.example.org'},
                {'type': 'dns', 'value': 'HOST2.example.org'},
            ]
        },
        account_id,
    )
    assert response.status_code == 201, response.json()
    assert sorted(identifier['value'] for identifier in response.json()['identifiers']) == ['host1.example.org', 'host2.example.org']

    authz_values = []
    for authz_url in response.json()['authorizations']:
        response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
        authz_values.append(response.json()['identifier']['value'])
    assert sorted(authz_values) == ['host1.example.org', 'host2.example.org']


def test_should_accept_ip_identifiers(signed_request, directory, allowed_ip_subnets):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {
            'identifiers': [
                {'type': 'ip', 'value': '192.0.2.1'},
                # uppercase IPv6 is lowercased and normalized to its compressed form
                {'type': 'ip', 'value': '2001:DB8:0000:0000:0000:0000:0000:0001'},
            ]
        },
        account_id,
    )
    assert response.status_code == 201, response.json()
    assert {(i['type'], i['value']) for i in response.json()['identifiers']} == {('ip', '192.0.2.1'), ('ip', '2001:db8::1')}, response.json()

    authz_values = []
    for authz_url in response.json()['authorizations']:
        response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
        authz_values.append(response.json()['identifier'])
    assert {(i['type'], i['value']) for i in authz_values} == {('ip', '192.0.2.1'), ('ip', '2001:db8::1')}


def test_should_reject_invalid_ip_identifiers(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'ip', 'value': 'not-an-ip'}]}, account_id)
    assert response.status_code == 400
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:malformed'
    assert 'invalid ip address' in response.json()['detail']


@pytest.mark.parametrize('value', ['dead:beef', ':', '::', 'fe80::'])
def test_should_reject_non_dns_values_as_dns_identifiers(signed_request, directory, value):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': value}]}, account_id)
    assert response.status_code == 400
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:malformed'
    assert 'invalid dns identifier' in response.json()['detail']


def test_should_reject_ip_identifiers_declared_as_dns(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    # an IP address must be requested with type "ip", not "dns"
    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': '192.0.2.1'}]}, account_id)
    assert response.status_code == 400
    assert response.json()['type'] == 'urn:ietf:params:acme:error:malformed'
    assert 'invalid dns identifier' in response.json()['detail']


def test_should_reject_identifiers_exceeding_max_length(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    # bounds the identifier length (and thus the regex input) to protect against pathological input
    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': 'a' * 254 + '.example.org'}]}, account_id)
    assert response.status_code == 400
    assert response.json()['type'] == 'urn:ietf:params:acme:error:malformed'
    assert 'exceeds max length' in response.json()['detail']


def test_should_reject_ip_identifiers_by_default(signed_request, directory):
    # acme_target_ip_subnets defaults to empty, so no ip certificates are allowed without opt-in
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'ip', 'value': '192.0.2.1'}]}, account_id)
    assert response.status_code == 400
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:rejectedIdentifier'
    assert 'acme_target_ip_subnets' in response.json()['detail']


def test_should_reject_ip_identifiers_outside_target_ip_subnets(signed_request, directory, monkeypatch):
    from ipaddress import ip_network

    from config import settings

    monkeypatch.setattr(settings.acme, 'target_ip_subnets', frozenset({ip_network('10.0.0.0/8')}))

    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'ip', 'value': '192.0.2.1'}]}, account_id)
    assert response.status_code == 400
    assert response.json()['type'] == 'urn:ietf:params:acme:error:rejectedIdentifier'
    assert 'acme_target_ip_subnets' in response.json()['detail']


def test_should_not_gate_ip_identifiers_by_target_domain_regex(signed_request, directory, allowed_ip_subnets, monkeypatch):
    import re

    from config import settings

    # the domain regex only applies to dns identifiers, so a domain-only pattern does not block ip orders
    monkeypatch.setattr(settings.acme, 'target_domain_regex', re.compile(r'[a-z-]+(\.[a-z-]+)+'))

    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'ip', 'value': '192.0.2.1'}]}, account_id)
    assert response.status_code == 201, response.json()
