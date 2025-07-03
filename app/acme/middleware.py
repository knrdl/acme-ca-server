import json
from typing import Generic, Literal, TypeVar

import db
import jwcrypto.jwk
import jwcrypto.jws
from config import settings
from fastapi import Body, Header, Request, Response, status
from jwcrypto.common import base64url_decode
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, constr, model_validator

from .exceptions import ACMEException
from .nonce import service as nonce_service


class RsaJwk(BaseModel):
    n: constr(min_length=1)  # type: ignore[valid-type]
    e: constr(min_length=1)  # type: ignore[valid-type]
    kty: Literal['RSA']


class EcJwk(BaseModel):
    crv: Literal['P-256']
    x: constr(min_length=1)  # type: ignore[valid-type]
    y: constr(min_length=1)  # type: ignore[valid-type]
    kty: Literal['EC']


PayloadT = TypeVar('PayloadT')


class RequestData(BaseModel, Generic[PayloadT]):
    payload: PayloadT
    key: jwcrypto.jwk.JWK
    account_id: str | None = None  # None if account does not exist
    new_nonce: str

    model_config = ConfigDict(arbitrary_types_allowed=True)


class Protected(BaseModel):
    # see https://www.rfc-editor.org/rfc/rfc8555#section-6.2
    alg: Literal['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']
    jwk: RsaJwk | EcJwk | None = None  # new user
    kid: str | None = None  # existing user
    nonce: constr(min_length=1)  # type: ignore[valid-type]
    url: AnyHttpUrl

    @model_validator(mode='after')
    def valid_check(self) -> 'Protected':
        if not self.jwk and not self.kid:
            raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='malformed', detail='either jwk or kid must be set')
        if self.jwk and self.kid:
            raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='malformed', detail='the fields jwk and kid are mutually exclusive')
        return self


class SignedRequest:  # pylint: disable=too-few-public-methods
    def __init__(
        self,
        payload_model: BaseModel | None = None,
        *,
        allow_new_account: bool = False,
        allow_blocked_account: bool = False,
    ):
        self.allow_new_account = allow_new_account
        self.allow_blocked_account = allow_blocked_account
        self.payload_model = payload_model

    @staticmethod
    def _schemeless_url(url: str):
        if url.startswith('https://'):
            return url.removeprefix('https://')
        elif url.startswith('http://'):
            return url.removeprefix('http://')
        return url

    async def __call__(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
        self,
        request: Request,
        response: Response,
        content_type: str = Header(..., pattern=r'^application/jose\+json$', description='Content Type must be "application/jose+json"'),
        protected: constr(min_length=1) = Body(...),  # type: ignore[valid-type]
        signature: constr(min_length=1) = Body(...),  # type: ignore[valid-type]
        payload: constr(min_length=0) = Body(...),  # type: ignore[valid-type]
    ):
        protected_data = Protected(**json.loads(base64url_decode(protected)))

        # Scheme might be different because of reverse proxy forwarding
        if self._schemeless_url(str(protected_data.url)) != self._schemeless_url(str(request.url)):
            raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='unauthorized', detail='Requested URL does not match with actually called URL')

        if protected_data.kid:  # account exists
            base_url = f'{settings.external_url}acme/accounts/'
            if not protected_data.kid.startswith(base_url):
                raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='malformed', detail=f'JWS invalid: kid must start with: "{base_url}"')

            account_id = protected_data.kid.split('/')[-1]
            if account_id:
                async with db.transaction(readonly=True) as sql:
                    if self.allow_blocked_account:
                        key_data = await sql.value("""select jwk from accounts where id = $1""", account_id)
                    else:
                        key_data = await sql.value("""select jwk from accounts where id = $1 and status = 'valid'""", account_id)
            else:
                key_data = None
            if not key_data:
                raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='accountDoesNotExist', detail='unknown, deactivated or revoked account')
            key = jwcrypto.jwk.JWK()
            key.import_key(**key_data)
        elif self.allow_new_account:
            if not protected_data.jwk:
                raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='badPublicKey', detail='JWK must be RSA or EC P-256')
            account_id = None
            key = jwcrypto.jwk.JWK()
            key.import_key(**protected_data.jwk.model_dump())
        else:
            raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='accountDoesNotExist', detail='unknown account. not accepting new accounts')

        jws = jwcrypto.jws.JWS()
        if 'none' in jws.allowed_algs:
            raise ValueError('"none" is a forbidden JWS algorithm!')
        try:
            # signature is checked here
            jws.deserialize(await request.body(), key)
        except jwcrypto.jws.InvalidJWSSignature as exc:
            raise ACMEException(status_code=status.HTTP_403_FORBIDDEN, exctype='unauthorized', detail='signature check failed') from exc

        if self.payload_model and payload:
            payload_data = self.payload_model(**json.loads(base64url_decode(payload)))  # type: ignore[operator]
        else:
            payload_data = None

        new_nonce = await nonce_service.refresh(protected_data.nonce)

        response.headers['Replay-Nonce'] = new_nonce
        # use append because there can be multiple Link-Headers with different rel targets
        response.headers.append('Link', f'<{settings.external_url}acme/directory>;rel="index"')

        return RequestData[self.payload_model](payload=payload_data, key=key, account_id=account_id, new_nonce=new_nonce)  # type: ignore[name-defined]
