from typing import Annotated

import db
from config import settings
from fastapi import APIRouter, Depends, Response, status
from logger import logger

from ..exceptions import ACMEException
from ..middleware import RequestData, SignedRequest
from . import service

api = APIRouter(tags=['acme:challenge'])


@api.post('/challenges/{chal_id}')
async def verify_challenge(response: Response, chal_id: str, data: Annotated[RequestData, Depends(SignedRequest())]):
    must_solve_challenge = False
    async with db.transaction() as sql:
        record = await sql.record("""
            select chal.authz_id, chal.error, chal.status, authz.status, authz.domain, chal.validated_at, chal.token, ord.id, ord.status from challenges chal
            join authorizations authz on authz.id = chal.authz_id
            join orders ord on authz.order_id = ord.id
            where chal.id = $1 and ord.account_id = $2 and ord.expires_at > now()
        """, chal_id, data.account_id)
        if not record:
            raise ACMEException(status_code=status.HTTP_404_NOT_FOUND, type='malformed', detail='specified challenge not available for current account')
        authz_id, chal_err, chal_status, authz_status, domain, chal_validated_at, token, order_id, order_status = record
        if order_status == 'invalid':
            await sql.exec("""update authorizations set status = 'invalid' where id = $1""", authz_id)
            await sql.value("""
                update challenges set status = 'invalid', error=row('unauthorized','order failed') where id = $1 and status <> 'invalid'
            """, chal_id)
            chal_status = 'invalid'
        if chal_status == 'pending' and order_status == 'pending':
            if authz_status == 'pending':
                must_solve_challenge = True
                chal_status = await sql.value("""update challenges set status = 'processing' where id = $1 returning status""", chal_id)
            else:
                await sql.value("""
                    update challenges set status='invalid', error=row('unauthorized','authorization failed') where id = $1 and status <> 'invalid'
                """, chal_id)
                chal_status = 'invalid'
    if chal_err:
        acme_error = ACMEException(type=chal_err.get('type'), detail=chal_err.get('detail'))
    else:
        acme_error = None

    # use append because there can be multiple Link-Headers with different rel targets
    response.headers.append('Link', f'<{settings.external_url}/authorization/{authz_id}>;rel="up"')

    if must_solve_challenge:
        try:
            await service.check_challenge_is_fulfilled(domain=domain, token=token, jwk=data.key)
            err = False
        except ACMEException as e:
            err = e
        except Exception as e:
            err = ACMEException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, type='serverInternal', detail=str(e))
            logger.warning('challenge failed for %s (account: %s)', domain, data.account_id, exc_info=True)
        if err is False:
            async with db.transaction() as sql:
                chal_status, chal_validated_at = await sql.record("""
                    update challenges set validated_at=now(), status = 'valid'
                    where id = $1 and status='processing' returning status, validated_at
                """, chal_id)
                await sql.exec("""
                    update authorizations set status = 'valid' where id = $1 and status = 'pending'
                """, authz_id)
                await sql.exec("""
                    update orders set status='ready' where id = $1 and status='pending' and
                    (select count(id) from authorizations where order_id = $1 and status <> 'valid') = 0
                """, order_id)  # set order to ready if all authzs are valid
        else:
            acme_error = err
            async with db.transaction() as sql:
                chal_status = await sql.value("""
                    update challenges set status = 'invalid', error=row($2,$3) where id = $1 returning status
                """, chal_id, err.exc_type, err.detail)
                await sql.exec("update authorizations set status = 'invalid' where id = $1", authz_id)
                await sql.exec("""
                    update orders set status = 'invalid', error=row('unauthorized', 'challenge failed') where id = $1
                """, order_id)

    return {
        'type': 'http-01',
        'url': f'{settings.external_url}/acme/challenges/{chal_id}',
        'status': chal_status,
        'validated': chal_validated_at,
        'token': token,
        'error': acme_error.value if acme_error else None
    }
