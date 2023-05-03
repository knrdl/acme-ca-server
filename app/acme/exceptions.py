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


class ACMEException(HTTPException):
    type: AcmeExceptionTypes
    detail_text: str
    value: dict[str, str]

    def __init__(self, *, type: AcmeExceptionTypes, detail: str = '',
                 status_code: int = status.HTTP_400_BAD_REQUEST, new_nonce: str = None) -> None:
        headers = {'Content-Type': 'application/problem+json'}
        if new_nonce:
            headers['Replay-Nonce'] = new_nonce
        self.type = type
        self.detail_text = detail
        self.value = {
            "type": "urn:ietf:params:acme:error:" + type, "detail": detail}
        super().__init__(status_code=status_code, detail=self.value, headers=headers)
