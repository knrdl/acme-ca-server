from .conftest import TestClient


def test_read_main(testclient: TestClient):
    response = testclient.get('/acme/directory')
    assert response.status_code == 200
    assert response.json()['newNonce'] == 'http://localhost:8000/acme/new-nonce'
