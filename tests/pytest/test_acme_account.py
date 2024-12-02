_mail_address = 'mailto:dummy@example.com'


def test_should_return_error_for_non_existing_accounts(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'onlyReturnExisting': True})

    assert response.status_code == 400
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:accountDoesNotExist'


def test_should_not_reflect_illegal_fields(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address], 'unknown': 'dummy', 'onlyReturnExisting': False})
    assert response.status_code == 201
    assert 'unknown' not in response.json()
    assert 'onlyReturnExisting' not in response.json()


def test_should_ignore_orders(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address], 'orders': 'http://localhost/dummy'})
    assert response.status_code == 201
    assert response.json()['orders'] != 'http://localhost/dummy'


def test_should_return_created_new_account_if_not_exist(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    assert response.status_code == 201
    assert response.headers['Location'].startswith('http://localhost:8000/acme/accounts/')
    assert len(response.headers['Location']) == len('http://localhost:8000/acme/accounts/') + 22

    assert response.json()['status'] == 'valid'
    assert response.json()['contact'] == [_mail_address]
    assert response.json()['orders'] == response.headers['Location'] + '/orders'


def test_should_return_existing_account(signed_request, directory):
    # signed_request uses both times the same jwk
    response1 = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    response2 = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})

    assert response1.status_code == 201
    assert response2.status_code == 200
    assert response1.headers['Location'] == response2.headers['Location']
    assert response1.json() == response2.json()
