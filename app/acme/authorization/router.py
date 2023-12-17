from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

import db
from config import settings

from ..exceptions import ACMEException
from ..middleware import RequestData, SignedRequest


class UpdateAuthzPayload(BaseModel):
    status: Literal['deactivated'] | None = None


api = APIRouter(tags=['acme:authorization'])


@api.post('/authorizations/{authz_id}')
async def view_or_update_authorization(
    authz_id: str,
    data: Annotated[RequestData[Optional[UpdateAuthzPayload]],
                    Depends(SignedRequest(Optional[UpdateAuthzPayload]))]
):
    async with db.transaction(readonly=True) as sql:
        record = await sql.record("""
            select authz.status, ord.status, ord.expires_at, authz.domain, chal.id, chal.token, chal.status, chal.validated_at
            from authorizations authz
            join challenges chal on chal.authz_id = authz.id
            join orders ord on authz.order_id = ord.id
            where authz.id = $1 and ord.account_id = $2
        """, authz_id, data.account_id)
    if record:
        authz_status, order_status, expires_at, domain, chal_id, chal_token, chal_status, chal_validated_at = record
        if data.payload and data.payload.status == 'deactivated':  # deactivate authz
            if authz_status in ['pending', 'valid'] and order_status in ['pending', 'ready']:
                async with db.transaction() as sql:
                    await sql.exec("""
                        update orders set status='invalid', error=row('unauthorized','authorization deactivated')
                        where id = (select order_id from authorizations where id = $1)
                    """, authz_id)
                    authz_status = await sql.value("update authorizations set status = 'deactivated' where id = $1 returning status", authz_id)
        chal = {
            'type': 'http-01',
            'url': f'{settings.external_url}acme/challenges/{chal_id}',
            'token': chal_token,
            'status': chal_status,
            'validated': chal_validated_at
        }

        return {
            'status': authz_status,
            'expires': expires_at,
            'identifier': {'type': 'dns', 'value': domain},
            'challenges': [{k: v for k, v in chal.items() if v is not None}],
        }
    else:
        raise ACMEException(status_code=status.HTTP_404_NOT_FOUND, exctype='malformed', detail='specified authorization not found for current account', new_nonce=data.new_nonce)


@api.post('/new-authz')
async def new_pre_authz(data: Annotated[RequestData, Depends(SignedRequest())]):
    raise ACMEException(status_code=status.HTTP_403_FORBIDDEN, exctype='unauthorized', detail='pre authorization is not supported', new_nonce=data.new_nonce)
