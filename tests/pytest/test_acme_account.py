import pydantic
import pytest

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


def test_should_create_account_with_empty_contact(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': []})
    assert response.status_code == 201
    assert response.json()['contact'] == []


def test_should_create_account_with_missing_contact(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': None})
    assert response.status_code == 201
    assert response.json()['contact'] == []


def test_should_create_account_without_contact(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    assert response.status_code == 201
    assert response.json()['contact'] == []


def test_should_update_account_contact(signed_request, directory):
    # create account without mail
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    assert response.status_code == 201
    assert response.json()['contact'] == []

    account_url = response.headers['Location']

    # set a mail addr and check
    response = signed_request(account_url, signed_request.nonce, {'contact': ['mailto:test123@example.com']}, account_url)
    assert response.status_code == 200, response.json()

    response = signed_request(account_url, signed_request.nonce, {}, account_url)
    assert response.status_code == 200
    assert response.json()['contact'] == ['mailto:test123@example.com']

    # don't remove mail addr and check is unchanged
    response = signed_request(account_url, signed_request.nonce, {}, account_url)
    assert response.status_code == 200, response.json()

    response = signed_request(account_url, signed_request.nonce, {}, account_url)
    assert response.status_code == 200
    assert response.json()['contact'] == ['mailto:test123@example.com']

    # remove mail addr and check
    response = signed_request(account_url, signed_request.nonce, {'contact': None}, account_url)
    assert response.status_code == 200, response.json()

    response = signed_request(account_url, signed_request.nonce, {}, account_url)
    assert response.status_code == 200
    assert response.json()['contact'] == []


def test_should_not_create_account_with_invalid_contact(signed_request, directory):
    with pytest.raises(pydantic.ValidationError) as excinfo:
        signed_request(directory['newAccount'], signed_request.nonce, {'contact': ['tel:1234']})
    assert 'NewAccountPayload' in str(excinfo.value)


def test_should_not_update_account_with_invalid_contact(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    assert response.status_code == 201
    assert response.json()['contact'] == []
    account_url = response.headers['Location']

    with pytest.raises(pydantic.ValidationError) as excinfo:
        response = signed_request(account_url, signed_request.nonce, {'contact': ['tel:1234']}, account_url)
    assert 'UpdateAccountPayload' in str(excinfo.value)


def test_should_return_existing_account(signed_request, directory):
    # signed_request uses both times the same jwk
    response1 = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    response2 = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})

    assert response1.status_code == 201
    assert response2.status_code == 200
    assert response1.headers['Location'] == response2.headers['Location']
    assert response1.json() == response2.json()


def test_should_update_account(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    assert response.status_code == 201
    account_url = response.headers['Location']

    response = signed_request(account_url, signed_request.nonce, {'contact': ['mailto:test@example.com'], 'status': 'deactivated'}, account_url)
    assert response.status_code == 200, response.json()

    response = signed_request(account_url, signed_request.nonce, {}, account_url)
    assert response.status_code == 200
    assert response.json()['status'] == 'deactivated'
    assert response.json()['contact'] == ['mailto:test@example.com']


def test_should_handle_account_mismatch(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    assert response.status_code == 201
    account_url = response.headers['Location']

    response = signed_request('http://localhost:8000/acme/accounts/hello123', signed_request.nonce, {}, account_url)
    assert response.status_code == 403
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:unauthorized'

    response = signed_request(account_url, signed_request.nonce, {}, 'http://localhost:8000/acme/accounts/hello123')
    assert response.status_code == 400
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:accountDoesNotExist'


def test_should_show_account_orders(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    assert response.status_code == 201
    account_url = response.headers['Location']
    orders_url = response.json()['orders']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': 'test.example.org'}]}, account_url)

    response = signed_request(orders_url, response.headers['Replay-Nonce'], '', account_url)
    assert response.status_code == 200
    assert len(response.json()['orders']) == 1
    assert response.json()['orders'][0].startswith('http://localhost:8000/acme/orders/'), response.json()
