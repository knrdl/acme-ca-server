from fastapi import FastAPI
import os

from fastapi.testclient import TestClient
import pytest

from app.constants import PROJECT_ROOT


@pytest.fixture
def fastapi_app() -> FastAPI:
    # TODO replace this with an randomly generated key
    os.environ["ca_encryption_key"] = "DaxNj1bTiCsk6aQiY43hz2jDqBZAU5kta1uNBzp_yqo="

    # can this be retrieved manually?
    os.environ["external_url"] = "http://testserver/"

    os.environ["db_dsn"] = (
        "postgresql://postgres:postgres@localhost/acme_ca_server_test"
    )
    os.environ["CA_CERT_PATH"] = str(PROJECT_ROOT / "ca.pem")
    os.environ["CA_PRIVATE_KEY_PATH"] = str(PROJECT_ROOT / "ca.key")
    from app.main import app

    return app


@pytest.fixture
def fastapi_testclient(fastapi_app: FastAPI) -> TestClient:
    with TestClient(fastapi_app) as ac:
        yield ac
