import json
from fastapi import FastAPI
from fastapi.testclient import TestClient


import base64


def test_acme_order(fastapi_testclient: TestClient):
    protected = {
        "alg": "ES256",
        "nonce": "testnonce",
        # This must be the same as the external_url env variable
        "url": "http://testserver/acme/new-order",
        # should be an account url
        "kid": "http://testserver/acme/accounts/1",
    }
    base64_protected_json = base64.urlsafe_b64encode(
        json.dumps(protected).encode()
    ).decode()

    request_data = {
        "payload": json.dumps({"notBefore": None, "notAfter": None}),
        "key": 1,
        "account_id": "123",
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
