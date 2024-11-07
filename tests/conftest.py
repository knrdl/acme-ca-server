from fastapi import FastAPI
import os

import pytest

@pytest.fixture
def fastapi_app() -> FastAPI:
    # TODO replace this with an randomly generated key
    os.environ['ca_encryption_key'] = 'DaxNj1bTiCsk6aQiY43hz2jDqBZAU5kta1uNBzp_yqo='
    os.environ['external_url'] = 'http://localhost:3001'
    
    os.environ['db_dsn'] = 'postgresql://postgres:postgres@localhost/acme_ca_server_test'
    
    from app.main import app
    
    return app