def test_should_ignore_duplicated_domains(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [
        {'type': 'dns', 'value': 'host1.example.org'},
        {'type': 'dns', 'value': 'host1.example.org'},
        {'type': 'dns', 'value': 'host2.example.org'},
    ]}, account_id)

    assert response.json()['status'] == 'pending', response.json()
    assert len(response.json()['authorizations']) == 2, response.json()


def test_should_reflect_order_on_create(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [
        {'type': 'dns', 'value': 'host1.example.org'},
        {'type': 'dns', 'value': 'host1.example.org'},
        {'type': 'dns', 'value': 'host2.example.org'},
    ]}, account_id)

    new_order_data = response.json()

    order_url = response.headers['Location']

    response = signed_request(order_url, response.headers['Replay-Nonce'], '', account_id)
    view_order_data = response.json()

    assert view_order_data == new_order_data


def test_should_handle_unknown_orders(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [
        {'type': 'dns', 'value': 'host1.example.org'},
    ]}, account_id)

    order_url = response.headers['Location']

    response = signed_request(order_url + '123', response.headers['Replay-Nonce'], '', account_id)
    assert response.status_code == 404
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:malformed'

    view_order_err = response.json()

    response = signed_request(order_url + '123/finalize', response.headers['Replay-Nonce'], {'csr': 'DEADBEEF'}, account_id)
    assert response.status_code == 404
    assert response.json() == view_order_err


