from fastapi.testclient import TestClient
from typing import Generator
import os
import shutil
import pytest
from pathlib import Path
import subprocess

import jwcrypto.jwk
import json


@pytest.fixture(scope='session')
def testclient() -> Generator[TestClient, None, None]:
    os.environ['ca_encryption_key'] = 'M8L6RSYPiHHr6GogXmkQIs7gVai_K5fDDJiNK7zUt0k='
    os.environ['external_url'] = 'http://localhost:8000/'

    ca_dir = Path(__file__).parent / 'import-ca'
    os.environ['ca_import_dir'] = str(ca_dir)
    shutil.rmtree(ca_dir, ignore_errors=True)
    ca_dir.mkdir()
    subprocess.call(['openssl', 'genrsa', '-out', ca_dir / 'ca.key', '4096'])
    subprocess.call(['openssl', 'req', '-new', '-x509', '-nodes', '-days', '3650', '-subj', '/C=DE/O=Demo', '-key', ca_dir / 'ca.key', '-out', ca_dir / 'ca.pem'])

    async def noop():
        pass

    import main

    # cronjobs are disabled because they would keep the test run going even if all tests are done
    main.ca.cronjob.start = noop
    main.acme.start_cronjobs = noop

    with TestClient(main.app) as tc:
        yield tc


@pytest.fixture(scope='session')
def directory(testclient: TestClient) -> dict[str, str]:
    return testclient.get('/acme/directory').json()


@pytest.fixture(scope='session')
def session_jwk() -> jwcrypto.jwk.JWK:
    # We only need one jwk per session
    jwk_key = jwcrypto.jwk.JWK.generate(kty='EC', crv='P-256')

    return jwk_key


@pytest.fixture
def signed_request(testclient: TestClient, session_jwk: jwcrypto.jwk.JWK, directory):
    class SignedRequest:
        @property
        def nonce(self):
            return testclient.head(directory['newNonce']).headers['Replay-Nonce']

        def __call__(self, url: str, nonce: str, payload: dict | str, account_url: str | None = None):
            jws = jwcrypto.jws.JWS('' if payload == '' else json.dumps(payload))
            protected = {'alg': 'ES256', 'nonce': nonce, 'url': url}
            if account_url is None:
                protected['jwk'] = session_jwk.export_public(as_dict=True)
            else:
                protected['kid'] = account_url

            jws.add_signature(session_jwk, protected=protected)

            return testclient.post(url, content=jws.serialize(), headers={'Content-Type': 'application/jose+json'})

    return SignedRequest()
