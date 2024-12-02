from unittest import mock
import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
import jwcrypto

from .utils import build_csr


_mail_address = 'mailto:dummy@example.com'
_host = 'example.com'


def test_should_revoke_certificate(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': _host}]}, account_id)
    authz_url = response.json()['authorizations'][0]
    finalize_order_url = response.json()['finalize']

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    challenge_token = response.json()['challenges'][0]['token']
    challenge_url = response.json()['challenges'][0]['url']

    mock_challenge_file_contents = f'{challenge_token}.{signed_request.account_jwk.thumbprint()}'.rstrip()

    with mock.patch(
        'app.acme.challenge.service.httpx.AsyncClient.get',
        return_value=httpx.Response(200, text=mock_challenge_file_contents),
    ) as mock_get:
        response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)

    mock_get.assert_called_once_with(f'http://{_host}:80/.well-known/acme-challenge/{challenge_token}')

    csr = build_csr([_host])

    response = signed_request(finalize_order_url, response.headers['Replay-Nonce'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))}, account_id)
    cert_url = response.json()['certificate']

    response = signed_request(cert_url, response.headers['Replay-Nonce'], {}, account_id)
    signed_cert = x509.load_pem_x509_certificate(response.content)

    assert signed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == _host
    assert signed_cert.public_key() == csr.public_key()

    response = signed_request(
        directory['revokeCert'], response.headers['Replay-Nonce'], {'certificate': jwcrypto.common.base64url_encode(signed_cert.public_bytes(Encoding.DER))}, account_id
    )
    assert response.status_code == 200
    assert response.headers['Content-Length'] == '0'
