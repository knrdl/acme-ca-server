import asyncio
from typing import Literal
from urllib.parse import urljoin

import httpx2
import jwcrypto.jwk
from config import USER_AGENT, settings
from fastapi import status
from logger import logger

from ..exceptions import ACMEException

CHALLENGE_VALIDATION_DEADLINE = 30
MAX_CHALLENGE_RESPONSE_SIZE = 1024


class UnallowedRedirect(Exception):
    pass


def redirect_is_allowed(*, domain: str, response: httpx2.Response) -> bool:
    if not response.is_redirect:
        return True

    location = response.headers.get('location')
    if not location:
        return False

    target = httpx2.URL(urljoin(str(response.request.url), location))
    target_host = target.host.lower() if target.host else ''

    if not target_host:
        return False

    if target_host in settings.acme.validation_redirect_hosts:
        return True

    # Always allow an HTTP-to-HTTPS upgrade on the challenged domain.
    # port 443 is the default and therefore set to None by httpx2.
    return target.scheme == 'https' and target.port is None and target_host == domain.lower()


def check_redirect(*, domain: str, response: httpx2.Response) -> None:
    if not response.is_redirect:
        return

    if not redirect_is_allowed(domain=domain, response=response):
        location = response.headers.get('location')
        target = str(httpx2.URL(urljoin(str(response.request.url), location))) if location else '<missing Location>'
        logger.warning(
            'ACME HTTP-01 validation redirect blocked | challenged_domain=%s | redirect_target=%s | reason: host not in ACME_VALIDATION_REDIRECT_HOSTS',
            domain,
            target,
        )
        raise UnallowedRedirect


async def check_challenge_is_fulfilled(*, domain: str, token: str, jwk: jwcrypto.jwk.JWK, new_nonce: str | None = None):
    try:
        await asyncio.wait_for(
            _check_challenge_is_fulfilled(domain=domain, token=token, jwk=jwk, new_nonce=new_nonce),
            timeout=CHALLENGE_VALIDATION_DEADLINE,
        )
    except asyncio.TimeoutError:
        raise ACMEException(
            status_code=status.HTTP_400_BAD_REQUEST,
            exctype='connection',
            detail='challenge validation deadline exceeded',
            new_nonce=new_nonce,
        ) from None


async def _check_challenge_is_fulfilled(*, domain: str, token: str, jwk: jwcrypto.jwk.JWK, new_nonce: str | None = None):
    for attempt in range(3):  # 3x retry
        err: Literal[False] | ACMEException
        try:

            async def check_redirect_hook(response: httpx2.Response) -> None:
                check_redirect(domain=domain, response=response)

            async with httpx2.AsyncClient(
                timeout=httpx2.Timeout(5, connect=3, read=10),
                headers={'User-Agent': USER_AGENT},
                verify=False,  # noqa: S501 (https cert check is intentionally disabled)
                http1=True,
                http2=False,
                follow_redirects=True,  # see redirect_is_allowed()
                max_redirects=10,
                trust_env=False,  # do not load proxy information from env vars
                limits=httpx2.Limits(max_connections=1, max_keepalive_connections=1),
                event_hooks={'response': [check_redirect_hook]},
            ) as client:
                async with client.stream('GET', f'http://{domain}:80/.well-known/acme-challenge/{token}') as res:
                    check_redirect(domain=domain, response=res)
                    response_body = bytearray()
                    response_too_large = False
                    if res.status_code == 200:
                        async for chunk in res.aiter_bytes(chunk_size=MAX_CHALLENGE_RESPONSE_SIZE + 1):
                            if len(response_body) + len(chunk) > MAX_CHALLENGE_RESPONSE_SIZE:
                                response_too_large = True
                                break
                            response_body.extend(chunk)
                if res.status_code == 200 and not response_too_large and bytes(response_body).rstrip() == f'{token}.{jwk.thumbprint()}'.encode():
                    err = False
                else:
                    err = ACMEException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        exctype='incorrectResponse',
                        detail='presented token does not match challenge',
                        new_nonce=new_nonce,
                    )
        except httpx2.TimeoutException:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='connection', detail='timeout', new_nonce=new_nonce)
        except httpx2.TooManyRedirects:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='incorrectResponse', detail='too many redirects', new_nonce=new_nonce)
        except httpx2.ConnectError:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='dns', detail='could not resolve address', new_nonce=new_nonce)
        except UnallowedRedirect:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='incorrectResponse', detail='redirect is not allowed', new_nonce=new_nonce)
        except Exception:  # noqa: BLE001
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='serverInternal', detail='could not validate challenge', new_nonce=new_nonce)
        if err is False:
            return  # check successful
        if attempt < 2:
            await asyncio.sleep(3)
    raise err  # type: ignore[misc]
