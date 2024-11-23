from fastapi.testclient import TestClient
from typing import Generator
import os
import shutil
import pytest
from pathlib import Path
import subprocess


@pytest.fixture
def testclient() -> TestClient:
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
