import asyncio

import httpx
import jwcrypto.jwk
from fastapi import status

from ..exceptions import ACMEException


async def check_challenge_is_fulfilled(
    *, domain: str, token: str, jwk: jwcrypto.jwk.JWK, new_nonce: str = None
):
    for _ in range(3):  # 3x retry
        err = True
        try:
            async with httpx.AsyncClient(
                timeout=10,
                # only http 1.0/1.1 is required, not https
                verify=False,
                http1=True,
                http2=False,  # noqa: S501 (https is intentionally disabled)
                # todo: redirects are forbidden for now, but RFC states redirects should be supported
                follow_redirects=False,
                trust_env=False,  # do not load proxy information from env vars
            ) as client:
                res = await client.get(
                    f"http://{domain}:80/.well-known/acme-challenge/{token}"
                )
                actual_text_content = res.text.rstrip()
                expected_text_content = f"{token}.{jwk.thumbprint()}"

                if (
                    res.status_code == 200
                    and actual_text_content == expected_text_content
                ):
                    err = False
                else:
                    err = ACMEException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        exctype="incorrectResponse",
                        detail="presented token does not match challenge",
                        new_nonce=new_nonce,
                    )
        except httpx.ConnectTimeout:
            err = ACMEException(
                status_code=status.HTTP_400_BAD_REQUEST,
                exctype="connection",
                detail="timeout",
                new_nonce=new_nonce,
            )
        except httpx.ConnectError:
            err = ACMEException(
                status_code=status.HTTP_400_BAD_REQUEST,
                exctype="dns",
                detail="could not resolve address",
                new_nonce=new_nonce,
            )
        except Exception:
            err = ACMEException(
                status_code=status.HTTP_400_BAD_REQUEST,
                exctype="serverInternal",
                detail="could not validate challenge",
                new_nonce=new_nonce,
            )
        if err is False:
            return  # check successful
        await asyncio.sleep(3)
    raise err
