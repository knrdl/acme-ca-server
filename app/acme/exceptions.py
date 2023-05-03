from typing import Literal
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
    'userActionRequired'
]


class ACMEException(Exception):
    type_: AcmeExceptionTypes
    detail: str
    headers: dict[str, str]
    status_code: int

    def __init__(
        self, *, type: AcmeExceptionTypes, detail: str = '',  # noqa: A002 (allow shadowing builtin "type")
        status_code: int = status.HTTP_400_BAD_REQUEST, new_nonce: str = None
    ) -> None:
        self.headers = {}
        if new_nonce:
            self.headers['Replay-Nonce'] = new_nonce
        self.type_ = type
        self.detail = detail
        self.status_code = status_code

    @property
    def value(self):
        return {'type': 'urn:ietf:params:acme:error:' + self.type_, 'detail': self.detail}

    def as_response(self):
        return JSONResponse(
            status_code=self.status_code,
            content=self.value,
            headers=self.headers,
            media_type='application/problem+json'
        )
