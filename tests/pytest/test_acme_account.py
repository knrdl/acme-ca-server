_mail_address = 'mailto:dummy@example.com'


def test_should_return_error_for_non_existing_accounts(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'onlyReturnExisting': True})

    assert response.status_code == 400
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:accountDoesNotExist'


def test_should_not_reflect_unknown_fields(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address], 'unknown': 'dummy'})
    assert response.status_code == 201
    assert 'unknown' not in response.json()
