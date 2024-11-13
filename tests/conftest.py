from typing import Generator
from fastapi import FastAPI
import os

from fastapi.testclient import TestClient
import pytest

from app.constants import PROJECT_ROOT
from jwcrypto import jwk

from tests.utils import generate_random_encryption_key


@pytest.fixture
def fastapi_app() -> FastAPI:
    os.environ['ca_encryption_key'] = generate_random_encryption_key()

    # This has to be set before importing the app
    os.environ['external_url'] = 'http://testserver/'

    # Before testing, make sure this connection is available
    os.environ['db_dsn'] = (
        'postgresql://postgres:postgres@localhost/acme_ca_server_test'
    )
    os.environ['CA_CERT_PATH'] = str(PROJECT_ROOT / 'ca.pem')
    os.environ['CA_PRIVATE_KEY_PATH'] = str(PROJECT_ROOT / 'ca.key')

    from app.main import app

    return app


@pytest.fixture
def fastapi_testclient(fastapi_app: FastAPI) -> Generator[TestClient]:
    with TestClient(fastapi_app, base_url=os.environ['external_url']) as ac:
        yield ac


@pytest.fixture(scope='session')
def jwk_key() -> jwk.JWK:
    # We only need one jwk per session
    jwk_key = jwk.JWK.generate(kty='EC', crv='P-256')

    return jwk_key
