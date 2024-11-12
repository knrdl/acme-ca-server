from fastapi.testclient import TestClient

from jwcrypto import jwk
from tests.utils import create_account_response, create_new_order_response, create_nonce


def test_create_new_account(fastapi_testclient: TestClient, jwk_key: jwk.JWK):
    nonce = create_nonce(fastapi_testclient)
    response = create_account_response(fastapi_testclient, nonce, jwk_key)

    assert response.is_success


def test_acme_order(fastapi_testclient: TestClient, jwk_key: jwk.JWK):
    account_nonce = create_nonce(fastapi_testclient)
    account_response = create_account_response(
        fastapi_testclient, account_nonce, jwk_key
    )

    response = create_new_order_response(fastapi_testclient, jwk_key, account_response)
    assert response.is_success
