from .conftest import TestClient


def test_get_certificates_page(testclient: TestClient):
    response = testclient.get('/certificates')
    assert response.status_code == 200, response.text

def test_get_domains_page(testclient: TestClient):
    response = testclient.get('/domains')
    assert response.status_code == 200, response.text

def test_download_non_existent_cert(testclient: TestClient):
    response = testclient.get('/certificates/DEADBEEF')
    assert response.status_code == 404, response.text
