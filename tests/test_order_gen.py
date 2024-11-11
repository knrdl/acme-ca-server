import json
from fastapi.testclient import TestClient


from jwcrypto.common import json_encode

import base64
from jwcrypto import jwk, jws


def create_nonce(testclient: TestClient):
    nonce_response = testclient.head("/acme/new-nonce")
    nonce_headers = nonce_response.headers

    assert nonce_response.is_success
    nonce = nonce_headers.get("Replay-Nonce")

    return nonce


def create_account_response(testclient: TestClient, nonce: str):
    # TODO replace this with self created public key
    jwk_key = jwk.JWK.generate(kty="EC", crv="P-256")
    jwk_export = jwk_key.export(private_key=False, as_dict=True)

    protected = {
        "alg": "ES256",
        "nonce": nonce,
        # This must be the same as the link we are posting
        "url": "http://testserver/acme/new-account",
        # should be an account url
        "jwk": jwk_export,
    }

    payload_data = {
        "termsOfServiceAgreed": True,
        "onlyReturnExisting": False,
        "contact": ["mailto:contact@basvandriel.nl"],
    }
    payload_encoded = json_encode(payload_data).encode("utf-8")

    jws_object = jws.JWS(payload_encoded)
    jws_object.add_signature(jwk_key, protected=json_encode(protected), alg="ES256")

    jws_serialized = json.loads(jws_object.serialize(compact=False))

    response = testclient.post(
        "/acme/new-account",
        headers={"Content-Type": "application/jose+json"},
        json=jws_serialized,
    )
    return response


def test_create_new_account(fastapi_testclient: TestClient):
    # Before order generation, create a nonce
    nonce = create_nonce(fastapi_testclient)
    response = create_account_response(fastapi_testclient, nonce)

    # TODO retrieve account id
    assert response.is_success


def test_acme_order(fastapi_testclient: TestClient):
    account_id = 1

    protected = {
        "alg": "ES256",
        "nonce": "testnonce",
        # This must be the same as the external_url env variable
        "url": "http://testserver/acme/new-order",
        # should be an account url
        "kid": f"http://testserver/acme/accounts/{account_id}",
    }
    base64_protected_json = base64.urlsafe_b64encode(
        json.dumps(protected).encode()
    ).decode()

    request_data = {
        "payload": json.dumps({"notBefore": None, "notAfter": None}),
        "key": 1,
        "account_id": None,
        "new_nonce": "123",
        "signature": "123",
        "protected": base64_protected_json,
    }
    request_content_type = "application/jose+json"
    x = fastapi_testclient.post(
        "/acme/new-order",
        json=request_data,
        headers={"Content-Type": request_content_type},
    )

    print(x)
