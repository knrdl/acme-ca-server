import json
from fastapi.testclient import TestClient
import httpx
from jwcrypto import jwk, jws

from tests.utils import (
    create_account_response,
    create_authorization_code_response,
    create_new_order_response,
    create_nonce,
)
from jwcrypto.common import json_encode

from unittest import mock


def test_challenge_fulfill(fastapi_testclient: TestClient, jwk_key: jwk.JWK):
    account_nonce = create_nonce(fastapi_testclient)
    account_response = create_account_response(
        fastapi_testclient, account_nonce, jwk_key
    )
    account_location_header = account_response.headers.get('location')

    response = create_new_order_response(fastapi_testclient, jwk_key, account_response)

    auth_response = create_authorization_code_response(
        fastapi_testclient, jwk_key, account_response, response
    )
    assert auth_response.is_success

    auth_codes_json = auth_response.json()
    challenges = auth_codes_json['challenges']

    # Retrieve the first challenge and it's URL
    first_challenge = challenges[0]
    challenge_url = first_challenge['url']
    challenge_token = first_challenge['token']

    # Retrieve the domain to put the token in
    domain = auth_codes_json['identifier']['value']

    challenge_nonce = create_nonce(fastapi_testclient)

    protected = {
        'alg': 'ES256',
        'nonce': challenge_nonce,
        'url': challenge_url,
        'kid': account_location_header,
    }
    payload_encoded = json_encode(None).encode('utf-8')

    jws_object = jws.JWS(payload_encoded)
    jws_object.add_signature(jwk_key, protected=json_encode(protected), alg='ES256')

    jws_serialized = json.loads(jws_object.serialize(compact=False))

    # rstrip the challenge contents like done in production
    mock_challenge_file_contents = f'{challenge_token}.{jwk_key.thumbprint()}'.rstrip()

    with mock.patch(
        'app.acme.challenge.service.httpx.AsyncClient.get',
        return_value=httpx.Response(200, text=mock_challenge_file_contents),
    ) as mock_get:
        response = fastapi_testclient.post(
            challenge_url,
            headers={'Content-Type': 'application/jose+json'},
            json=jws_serialized,
        )
        assert response.is_success

    mock_get.assert_called_once_with(
        f'http://{domain}:80/.well-known/acme-challenge/{challenge_token}'
    )
