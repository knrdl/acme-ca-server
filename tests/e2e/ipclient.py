"""End-to-end ACME client for IP address certificates, invoked by run.sh.

The IP address to request is passed at runtime (read from the challenge container
by run.sh); no address is hardcoded here.

Usage: python ipclient.py <ip> <challenge-dir>
"""

import json
import os
import sys
import time
from ipaddress import ip_address

import httpx2 as httpx
import jwcrypto.common
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwk, jws

DIRECTORY_URL = os.environ.get('ACME_DIRECTORY', 'http://acme.example.org:8080/acme/directory')
JOSE = 'application/jose+json'

key = jwk.JWK.generate(kty='EC', crv='P-256')
PUBLIC_JWK = json.loads(key.export_public())
THUMBPRINT = key.thumbprint()


def fail(msg):
    print(f'FAIL: {msg}', file=sys.stderr)
    sys.exit(1)


class AcmeClient:
    def __init__(self):
        self.http = httpx.Client(timeout=30)
        self.directory = self.http.get(DIRECTORY_URL).json()
        self.nonce = None
        self.kid = None

    def _next_nonce(self):
        if self.nonce:
            nonce, self.nonce = self.nonce, None
            return nonce
        res = self.http.head(self.directory['newNonce'])
        if res.status_code >= 400:
            res = self.http.get(self.directory['newNonce'])
        res.raise_for_status()
        return res.headers['Replay-Nonce']

    def post(self, url, payload):
        protected = {'alg': 'ES256', 'nonce': self._next_nonce(), 'url': url}
        if self.kid:
            protected['kid'] = self.kid
        else:
            protected['jwk'] = PUBLIC_JWK
        body = jws.JWS(json.dumps(payload) if payload != '' else '')
        body.add_signature(key, protected=protected)
        res = self.http.post(url, content=body.serialize(), headers={'Content-Type': JOSE})
        if 'Replay-Nonce' in res.headers:
            self.nonce = res.headers['Replay-Nonce']
        return res

    def post_as_get(self, url):
        return self.post(url, '')

    def register(self, mail):
        res = self.post(self.directory['newAccount'], {'termsOfServiceAgreed': True, 'contact': [f'mailto:{mail}']})
        if res.status_code != 201:
            fail(f'new account failed: {res.status_code} {res.text}')
        self.kid = res.headers['Location']


def is_malformed(res, needle):
    try:
        body = res.json()
    except ValueError:
        return False
    return res.status_code >= 400 and 'problem+json' in res.headers.get('Content-Type', '') and body.get('type', '').endswith(':malformed') and needle in body.get('detail', '')


def reject_invalid_ip(client):
    res = client.post(client.directory['newOrder'], {'identifiers': [{'type': 'ip', 'value': 'not-an-ip'}]})
    if not is_malformed(res, 'invalid ip address'):
        fail(f'invalid ip identifier was not rejected: {res.status_code} {res.text}')
    print('invalid ip identifier rejected')


def issue_certificate(client, ip, challenge_dir):
    res = client.post(client.directory['newOrder'], {'identifiers': [{'type': 'ip', 'value': ip}]})
    if res.status_code != 201:
        fail(f'new order for {ip} failed: {res.status_code} {res.text}')
    order = res.json()
    if order['identifiers'] != [{'type': 'ip', 'value': ip}]:
        fail(f'order echoed an unexpected identifier: {order["identifiers"]}')

    authz_url = order['authorizations'][0]
    authz = client.post_as_get(authz_url).json()
    if authz['identifier'] != {'type': 'ip', 'value': ip}:
        fail(f'authorization has an unexpected identifier: {authz["identifier"]}')

    challenge = authz['challenges'][0]
    token = challenge['token']
    challenge_file = os.path.join(challenge_dir, '.well-known', 'acme-challenge', token)
    os.makedirs(os.path.dirname(challenge_file), exist_ok=True)
    with open(challenge_file, 'w', encoding='utf-8') as f:
        f.write(f'{token}.{THUMBPRINT}')

    client.post(challenge['url'], {})
    status = authz['status']
    for _ in range(15):
        status = client.post_as_get(authz_url).json()['status']
        if status in ('valid', 'invalid'):
            break
        time.sleep(1)
    if status != 'valid':
        fail(f'http-01 challenge for {ip} was not validated (status: {status})')

    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address(ip))]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    res = client.post(order['finalize'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(serialization.Encoding.DER))})
    finalized = res.json()
    if finalized.get('status') != 'valid' or not finalized.get('certificate'):
        fail(f'finalize failed: {res.status_code} {res.text}')

    cert = x509.load_pem_x509_certificate(client.post_as_get(finalized['certificate']).content)
    sans = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    if [str(value) for value in sans.get_values_for_type(x509.IPAddress)] != [ip_address(ip).compressed]:
        fail(f'certificate SAN does not contain the requested IP: {sans}')
    if sans.get_values_for_type(x509.DNSName):
        fail('certificate SAN unexpectedly contains DNS names')
    if len(cert.subject) != 0:
        fail('an IP-only certificate must have an empty subject (no common name)')
    print(f'issued and verified a certificate for IP {ip}')


def main():
    if len(sys.argv) != 3:
        fail('usage: ipclient.py <ip> <challenge-dir>')
    ip, challenge_dir = sys.argv[1], sys.argv[2]

    client = AcmeClient()
    client.register('ipclient@example.org')
    reject_invalid_ip(client)
    issue_certificate(client, ip, challenge_dir)
    print('IP identifier e2e test passed')


if __name__ == '__main__':
    main()
