import json
from typing import Any, Generic, Literal, Optional, TypeVar, Union
from pydantic import AnyHttpUrl, BaseModel, constr, root_validator
from fastapi import Response, Body, Request, Header, status
from .exceptions import ACMEException
from config import settings
from .nonce import service as nonce_service
from jwcrypto.common import base64url_decode
import jwcrypto.jwk
import jwcrypto.jws
import db
from pydantic.generics import GenericModel


class RsaJwk(BaseModel):
    n: constr(min_length=1)
    e: constr(min_length=1)
    kty: Literal['RSA']


class EcJwk(BaseModel):
    crv: Literal['P-256']
    x: constr(min_length=1)
    y: constr(min_length=1)
    kty: Literal['EC']


PayloadT = TypeVar('PayloadT')


class RequestData(GenericModel, Generic[PayloadT]):
    payload: PayloadT
    key: jwcrypto.jwk.JWK
    account_id: Optional[str]  # None if account does not exist


class Protected(BaseModel):
    # see https://www.rfc-editor.org/rfc/rfc8555#section-6.2
    alg: Literal['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']
    jwk: Optional[Union[RsaJwk, EcJwk]]  # new user
    kid: Optional[str]  # existing user
    nonce: constr(min_length=1)
    url: AnyHttpUrl

    @root_validator
    def valid_check(cls, values: dict[str, Any]) -> dict[str, Any]:
        if not values.get('jwk') and not values.get('kid'):
            raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST,
                                type='malformed', detail='either jwk or kid must be set')
        if values.get('jwk') and values.get('kid'):
            raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, type='malformed',
                                detail='the fields jwk and kid are mutually exclusive')
        return values


class SignedRequest:
    def __init__(self, payload_model: BaseModel = None, *,
                 allow_new_account: bool = False, allow_blocked_account: bool = False):
        self.allow_new_account = allow_new_account
        self.allow_blocked_account = allow_blocked_account
        self.payload_model = payload_model

    @staticmethod
    def _schemeless_url(url: str):
        if url.startswith('https://'):
            return url.removeprefix('https://')
        if url.startswith('http://'):
            return url.removeprefix('http://')
        return url

    async def __call__(self, request: Request, response: Response, content_type: str = Header(..., regex=r'^application/jose\+json$', description='Content Type must be "application/jose+json"'), protected: constr(min_length=1) = Body(...), signature: constr(min_length=1) = Body(...), payload: constr(min_length=0) = Body(...)):
        protected_data = Protected(**json.loads(base64url_decode(protected)))

        # Scheme might be different because of reverse proxy forwarding
        if self._schemeless_url(protected_data.url) != self._schemeless_url(str(request.url)):
            raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, type="unauthorized",
                                detail='Requested URL does not match with actually called URL')

        if protected_data.kid:  # account exists
            base_url = f'{settings.external_url}/acme/accounts/'
            if not protected_data.kid.startswith(base_url):
                raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, type="malformed",
                                    detail=f'JWS invalid: kid must start with: "{base_url}"')

            account_id = protected_data.kid.split('/')[-1]
            if account_id:
                async with db.transaction(readonly=True) as sql:
                    if self.allow_blocked_account:
                        key_data = await sql.value("select jwk from accounts where id = $1", account_id)
                    else:
                        key_data = await sql.value("select jwk from accounts where id = $1 and status = 'valid'", account_id)
            else:
                key_data = None
            if not key_data:
                raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST,
                                    type="accountDoesNotExist", detail='unknown, deactived or revoked account')
            key = jwcrypto.jwk.JWK()
            key.import_key(**key_data)
        elif self.allow_new_account:
            account_id = None
            key = jwcrypto.jwk.JWK()
            key.import_key(**protected_data.jwk.dict())
        else:
            raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST,
                                type="accountDoesNotExist", detail='unknown account. not accepting new accounts')

        jws = jwcrypto.jws.JWS()
        if "none" in jws.allowed_algs:
            raise Exception('"none" is a forbidden JWS algorithm!')
        try:
            # signature is checked here
            jws.deserialize(await request.body(), key)
        except jwcrypto.jws.InvalidJWSSignature as e:
            raise ACMEException(status_code=status.HTTP_403_FORBIDDEN,
                                type='unauthorized', detail="signature check failed")

        if self.payload_model and payload:
            payload_data = self.payload_model(
                **json.loads(base64url_decode(payload)))
        else:
            payload_data = None

        new_nonce = await nonce_service.refresh(protected_data.nonce)

        response.headers["Replay-Nonce"] = new_nonce
        # use append because there can be multiple Link-Headers with different rel targets
        response.headers.append(
            'Link', f'<{settings.external_url}/acme/directory>;rel="index"')

        return RequestData[self.payload_model](payload=payload_data, key=key, account_id=account_id)
