import asyncio

import pytest
from acme.challenge import service
from acme.exceptions import ACMEException


def test_challenge_validation_deadline(monkeypatch, account_jwk):
    class SlowClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        def stream(self, *_args):
            return SlowResponse()

    class SlowResponse:
        async def __aenter__(self):
            await asyncio.sleep(10)

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(service.httpx2, 'AsyncClient', SlowClient)
    monkeypatch.setattr(service, 'CHALLENGE_VALIDATION_DEADLINE', 1)

    with pytest.raises(ACMEException) as exc_info:
        asyncio.run(service.check_challenge_is_fulfilled(domain='example.org', token='token', jwk=account_jwk))

    assert exc_info.value.exc_type == 'connection'
    assert exc_info.value.detail == 'challenge validation deadline exceeded'


def test_challenge_validation_rejects_oversized_response(monkeypatch, account_jwk):
    class OversizedResponse:
        status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def aiter_bytes(self, *, chunk_size):
            yield b'x' * chunk_size

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        def stream(self, *_args):
            return OversizedResponse()

    async def no_sleep(_delay):
        pass

    monkeypatch.setattr(service.httpx2, 'AsyncClient', Client)
    monkeypatch.setattr(service.asyncio, 'sleep', no_sleep)

    with pytest.raises(ACMEException) as exc_info:
        asyncio.run(service.check_challenge_is_fulfilled(domain='example.org', token='token', jwk=account_jwk))

    assert exc_info.value.exc_type == 'incorrectResponse'
