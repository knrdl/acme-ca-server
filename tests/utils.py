import json
from fastapi.testclient import TestClient

from jwcrypto.common import json_encode

from jwcrypto import jwk, jws


def create_nonce(testclient: TestClient):
    nonce_response = testclient.head("/acme/new-nonce")
    nonce_headers = nonce_response.headers

    assert nonce_response.is_success
    nonce = nonce_headers.get("Replay-Nonce")

    return nonce


def create_account_response(testclient: TestClient, nonce: str, jwk_key: jwk.JWK):
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


def create_new_order_response(testclient: TestClient, jwk_key: jwk.JWK):
    nonce = create_nonce(testclient)

    account_response = create_account_response(testclient, nonce, jwk_key)
    account_location_header = account_response.headers.get("location")

    order_nonce = create_nonce(testclient)

    protected = {
        "alg": "ES256",
        "nonce": order_nonce,
        "url": "http://testserver/acme/new-order",
        # should be an account url
        "kid": account_location_header,
    }

    payload = {
        "notBefore": None,
        "notAfter": None,
        "identifiers": [{"type": "dns", "value": "domain.example.com"}],
    }
    payload_encoded = json_encode(payload).encode("utf-8")

    jws_object = jws.JWS(payload_encoded)
    jws_object.add_signature(jwk_key, protected=json_encode(protected), alg="ES256")

    jws_serialized = json.loads(jws_object.serialize(compact=False))

    request_content_type = "application/jose+json"
    response = testclient.post(
        "/acme/new-order",
        json=jws_serialized,
        headers={"Content-Type": request_content_type},
    )
    return response
