from .conftest import TestClient


def test_show_directory(testclient: TestClient):
    response = testclient.get('/acme/directory')
    assert response.status_code == 200
    assert response.json() == {
        'newNonce': 'http://localhost:8000/acme/new-nonce', 
        'newAccount': 'http://localhost:8000/acme/new-account', 
        'newOrder': 'http://localhost:8000/acme/new-order', 
        'revokeCert': 'http://localhost:8000/acme/revoke-cert', 
        'keyChange': 'http://localhost:8000/acme/key-change', 
        'meta': {'website': 'http://localhost:8000/'}
    }
