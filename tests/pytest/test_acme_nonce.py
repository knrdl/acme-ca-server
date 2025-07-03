import datetime
import re

import jwcrypto

from .conftest import TestClient


def test_generate_nonce(testclient: TestClient, directory):
    response = testclient.get(directory['newNonce'])
    assert response.status_code == 204
    nonce = response.headers['Replay-Nonce']
    assert len(nonce) == 43
    assert re.match('^[A-Za-z0-9_-]+$', nonce)
    assert len(jwcrypto.common.base64url_decode(nonce)) >= 128 // 8, 'minimum 128bit entropy'
    response2 = testclient.head(directory['newNonce'])
    nonce2 = response2.headers['Replay-Nonce']
    assert nonce != nonce2


def test_should_fail_on_bad_nonce(signed_request, directory):
    response = signed_request(directory['newAccount'], 'not-a-correct-nonce', {'contact': ['mailto:dummy@example.com']})

    assert response.status_code == 400
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:badNonce'
    assert response.json()['detail'] == 'old nonce is wrong'


def test_should_persist_new_nonce_with_expiration(testclient: TestClient, directory, db) -> None:
    nonce = testclient.get(directory['newNonce']).headers['Replay-Nonce']

    age, *_ = db.fetch_row('select expires_at - now() from nonces where id=$1', nonce)
    assert datetime.timedelta(minutes=29, seconds=59) < age < datetime.timedelta(minutes=30, milliseconds=50)
