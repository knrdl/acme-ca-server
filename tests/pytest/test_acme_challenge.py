import asyncio

import pytest

from .conftest import TestClient


@pytest.mark.parametrize(
    ('location', 'expected'),
    [
        ('https://example.org/.well-known/acme-challenge/token', True),
        ('http://example.org/.well-known/acme-challenge/token', False),
        ('https://other.example/.well-known/acme-challenge/token', False),
        ('https://example.org:8443/.well-known/acme-challenge/token', False),
    ],
)
def test_http_to_https_redirect_policy(testclient: TestClient, monkeypatch, location: str, expected: bool):
    from acme.challenge import service

    monkeypatch.setattr(service.settings.acme, 'validation_redirects', 'http-to-https')
    request = service.httpx2.Request('GET', 'http://example.org/.well-known/acme-challenge/token')
    response = service.httpx2.Response(302, headers={'location': location}, request=request)

    assert service.redirect_is_allowed(domain='example.org', response=response) is expected


def test_open_redirect_policy_allows_redirect_to_other_host(testclient: TestClient, monkeypatch):
    from acme.challenge import service

    monkeypatch.setattr(service.settings.acme, 'validation_redirects', 'open')
    request = service.httpx2.Request('GET', 'http://example.org/.well-known/acme-challenge/token')
    response = service.httpx2.Response(302, headers={'location': 'http://internal.example:8080/path'}, request=request)

    assert service.redirect_is_allowed(domain='example.org', response=response)


def test_challenge_validation_deadline(testclient: TestClient, monkeypatch, account_jwk):
    from acme.challenge import service
    from acme.exceptions import ACMEException

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
        is_redirect = False

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


def test_challenge_validation_rejects_oversized_response(testclient: TestClient, monkeypatch, account_jwk):
    from acme.challenge import service
    from acme.exceptions import ACMEException

    class OversizedResponse:
        status_code = 200
        is_redirect = False

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

    with pytest.raises(ACMEException) as exc_info:
        asyncio.run(service.check_challenge_is_fulfilled(domain='example.org', token='token', jwk=account_jwk))

    assert exc_info.value.exc_type == 'incorrectResponse'
