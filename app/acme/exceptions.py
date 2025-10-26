from typing import Literal

from config import settings
from fastapi import status
from fastapi.responses import JSONResponse

AcmeExceptionTypes = Literal[
    'accountDoesNotExist',
    'alreadyRevoked',
    'badCSR',
    'badNonce',
    'badPublicKey',
    'badRevocationReason',
    'badSignatureAlgorithm',
    'caa',
    'compound',
    'connection',
    'dns',
    'externalAccountRequired',
    'incorrectResponse',
    'invalidContact',
    'malformed',
    'orderNotReady',
    'rateLimited',
    'rejectedIdentifier',
    'serverInternal',
    'tls',
    'unauthorized',
    'unsupportedContact',
    'unsupportedIdentifier',
    'userActionRequired',
]


class ACMEException(Exception):
    exc_type: AcmeExceptionTypes
    detail: str
    headers: dict[str, str]
    status_code: int
    new_nonce: str | None

    def __init__(  # noqa: B042
        self,
        *,
        exctype: AcmeExceptionTypes,
        detail: str = '',
        status_code: int = status.HTTP_400_BAD_REQUEST,
        new_nonce: str | None = None,
    ) -> None:
        self.headers = {'Link': f'<{settings.external_url}acme/directory>;rel="index"'}
        # when a new nonce is already created it should also be used in the exception case
        # however if there is none yet, a new one gets generated in as_response()
        self.new_nonce = new_nonce
        self.exc_type = exctype
        self.detail = detail
        self.status_code = status_code

        super().__init__(self.value)

    @property
    def value(self):
        return {'type': 'urn:ietf:params:acme:error:' + self.exc_type, 'detail': self.detail}

    async def as_response(self):
        if not self.new_nonce:
            from .nonce.service import generate as generate_nonce  # import here to prevent circular import  # pylint: disable=import-outside-toplevel

            self.new_nonce = await generate_nonce()
        return JSONResponse(
            status_code=self.status_code,
            content=self.value,
            headers=dict(self.headers, **{'Replay-Nonce': self.new_nonce}),
            media_type='application/problem+json',
        )

    def __repr__(self) -> str:
        return f'ACME-Exception({self.value})'
