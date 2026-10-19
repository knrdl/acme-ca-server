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
