from .conftest import TestClient

def test_generate_nonce(testclient: TestClient):
    response = testclient.get('/acme/new-nonce')
    assert response.status_code == 204
    nonce = response.headers['Replay-Nonce']
    assert len(nonce) == 43
    response2 = testclient.head('/acme/new-nonce')
    nonce2 = response2.headers['Replay-Nonce']
    assert nonce != nonce2
