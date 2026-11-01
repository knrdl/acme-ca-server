from unittest import mock

import httpx2
import jwcrypto
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .utils import build_csr, build_ip_csr, build_mixed_csr

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
        'app.acme.challenge.service.httpx2.AsyncClient.get',
        return_value=httpx2.Response(200, text=mock_challenge_file_contents),
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

    response = signed_request(
        directory['revokeCert'], response.headers['Replay-Nonce'], {'certificate': jwcrypto.common.base64url_encode(signed_cert.public_bytes(Encoding.DER))}, account_id
    )
    assert response.status_code == 400
    assert response.headers['Content-Type'] == 'application/problem+json'
    assert response.json()['type'] == 'urn:ietf:params:acme:error:alreadyRevoked'


def test_should_issue_certificate_for_mixed_case_domains(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': 'Mixed.Example.COM'}]}, account_id)
    assert response.json()['identifiers'] == [{'type': 'dns', 'value': 'mixed.example.com'}]
    authz_url = response.json()['authorizations'][0]
    finalize_order_url = response.json()['finalize']

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    challenge_token = response.json()['challenges'][0]['token']
    challenge_url = response.json()['challenges'][0]['url']

    mock_challenge_file_contents = f'{challenge_token}.{signed_request.account_jwk.thumbprint()}'.rstrip()

    with mock.patch(
        'app.acme.challenge.service.httpx2.AsyncClient.get',
        return_value=httpx2.Response(200, text=mock_challenge_file_contents),
    ) as mock_get:
        response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)

    mock_get.assert_called_once_with(f'http://mixed.example.com:80/.well-known/acme-challenge/{challenge_token}')

    csr = build_csr(['MIXED.example.com'])

    response = signed_request(finalize_order_url, response.headers['Replay-Nonce'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))}, account_id)
    assert response.json()['status'] == 'valid', response.json()

    response = signed_request(response.json()['certificate'], response.headers['Replay-Nonce'], {}, account_id)
    signed_cert = x509.load_pem_x509_certificate(response.content)
    assert signed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == 'mixed.example.com'


def _solve_challenge(signed_request, authz_response):
    """Extract the challenge token, url and the expected challenge file contents from an authorization response."""
    challenge_token = authz_response.json()['challenges'][0]['token']
    challenge_url = authz_response.json()['challenges'][0]['url']
    mock_challenge_file_contents = f'{challenge_token}.{signed_request.account_jwk.thumbprint()}'.rstrip()
    return challenge_token, challenge_url, mock_challenge_file_contents


def test_should_issue_certificate_for_ip_address(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    account_id = response.headers['Location']

    ip = '192.0.2.1'
    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'ip', 'value': ip}]}, account_id)
    assert response.status_code == 201, response.json()
    assert response.json()['identifiers'] == [{'type': 'ip', 'value': ip}]
    authz_url = response.json()['authorizations'][0]
    finalize_order_url = response.json()['finalize']

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    assert response.json()['identifier'] == {'type': 'ip', 'value': ip}, response.json()
    challenge_token, challenge_url, mock_challenge_file_contents = _solve_challenge(signed_request, response)

    with mock.patch(
        'app.acme.challenge.service.httpx2.AsyncClient.get',
        return_value=httpx2.Response(200, text=mock_challenge_file_contents),
    ) as mock_get:
        response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)

    mock_get.assert_called_once_with(f'http://{ip}:80/.well-known/acme-challenge/{challenge_token}')
    assert response.json()['status'] == 'valid', response.json()

    csr = build_ip_csr([ip])
    response = signed_request(finalize_order_url, response.headers['Replay-Nonce'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))}, account_id)
    assert response.json()['status'] == 'valid', response.json()

    response = signed_request(response.json()['certificate'], response.headers['Replay-Nonce'], {}, account_id)
    signed_cert = x509.load_pem_x509_certificate(response.content)

    sans = signed_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert [str(ip) for ip in sans.get_values_for_type(x509.IPAddress)] == [ip]
    assert sans.get_values_for_type(x509.DNSName) == []
    assert len(signed_cert.subject) == 0  # no common name for an IP-only certificate
    assert signed_cert.public_key() == csr.public_key()


def test_should_issue_certificate_for_ipv6_address(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    account_id = response.headers['Location']

    ip = '2001:db8::1'
    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'ip', 'value': ip}]}, account_id)
    assert response.status_code == 201, response.json()
    authz_url = response.json()['authorizations'][0]
    finalize_order_url = response.json()['finalize']

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    assert response.json()['identifier'] == {'type': 'ip', 'value': ip}, response.json()
    challenge_token, challenge_url, mock_challenge_file_contents = _solve_challenge(signed_request, response)

    with mock.patch(
        'app.acme.challenge.service.httpx2.AsyncClient.get',
        return_value=httpx2.Response(200, text=mock_challenge_file_contents),
    ) as mock_get:
        response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)

    # IPv6 literals are enclosed in square brackets in the challenge URL
    mock_get.assert_called_once_with(f'http://[{ip}]:80/.well-known/acme-challenge/{challenge_token}')
    assert response.json()['status'] == 'valid', response.json()

    csr = build_ip_csr([ip])
    response = signed_request(finalize_order_url, response.headers['Replay-Nonce'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))}, account_id)
    assert response.json()['status'] == 'valid', response.json()

    response = signed_request(response.json()['certificate'], response.headers['Replay-Nonce'], {}, account_id)
    signed_cert = x509.load_pem_x509_certificate(response.content)
    sans = signed_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert [str(ip) for ip in sans.get_values_for_type(x509.IPAddress)] == [ip]
    assert signed_cert.public_key() == csr.public_key()


def test_should_issue_certificate_for_mixed_domain_and_ip(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [_mail_address]})
    account_id = response.headers['Location']

    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {'identifiers': [{'type': 'dns', 'value': 'host1.example.org'}, {'type': 'ip', 'value': '192.0.2.1'}]},
        account_id,
    )
    assert response.status_code == 201, response.json()
    assert {(i['type'], i['value']) for i in response.json()['identifiers']} == {('dns', 'host1.example.org'), ('ip', '192.0.2.1')}
    authz_urls = response.json()['authorizations']
    finalize_order_url = response.json()['finalize']

    for authz_url in authz_urls:
        response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
        _challenge_token, challenge_url, mock_challenge_file_contents = _solve_challenge(signed_request, response)
        with mock.patch(
            'app.acme.challenge.service.httpx2.AsyncClient.get',
            return_value=httpx2.Response(200, text=mock_challenge_file_contents),
        ):
            response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)
        assert response.json()['status'] == 'valid', response.json()

    csr = build_mixed_csr(['host1.example.org'], ['192.0.2.1'])
    response = signed_request(finalize_order_url, response.headers['Replay-Nonce'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))}, account_id)
    assert response.json()['status'] == 'valid', response.json()

    response = signed_request(response.json()['certificate'], response.headers['Replay-Nonce'], {}, account_id)
    signed_cert = x509.load_pem_x509_certificate(response.content)
    # the common name is the domain name, the SAN contains both the domain and the IP address
    assert signed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == 'host1.example.org'
    sans = signed_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert [str(name) for name in sans.get_values_for_type(x509.DNSName)] == ['host1.example.org']
    assert [str(ip) for ip in sans.get_values_for_type(x509.IPAddress)] == ['192.0.2.1']
