from .conftest import TestClient


def test_show_directory(testclient: TestClient):
    response = testclient.get('/acme/directory')
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/json'
    assert response.json() == {
        'newNonce': 'http://localhost:8000/acme/new-nonce',
        'newAccount': 'http://localhost:8000/acme/new-account',
        'newOrder': 'http://localhost:8000/acme/new-order',
        'revokeCert': 'http://localhost:8000/acme/revoke-cert',
        'keyChange': 'http://localhost:8000/acme/key-change',
        'meta': {'website': 'http://localhost:8000/'},
    }


def test_directory_shows_terms(testclient: TestClient, monkeypatch):
    import config

    monkeypatch.setattr(config.settings.acme, 'terms_of_service_url', 'https://example.com/terms.html')
    response = testclient.get('/acme/directory')
    assert response.status_code == 200
    assert response.json() == {
        'newNonce': 'http://localhost:8000/acme/new-nonce',
        'newAccount': 'http://localhost:8000/acme/new-account',
        'newOrder': 'http://localhost:8000/acme/new-order',
        'revokeCert': 'http://localhost:8000/acme/revoke-cert',
        'keyChange': 'http://localhost:8000/acme/key-change',
        'meta': {'termsOfService': 'https://example.com/terms.html', 'website': 'http://localhost:8000/'},
    }
