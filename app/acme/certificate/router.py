from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, Response, status
from jwcrypto.common import base64url_decode
from pydantic import BaseModel, constr

import db
from ca import service as ca_service

from ..exceptions import ACMEException
from ..middleware import RequestData, SignedRequest
from .service import SerialNumberConverter, parse_cert


class RevokeCertPayload(BaseModel):
    certificate: constr(min_length=1, max_length=1 * 1024**2)
    reason: int | None = None  # not evaluated


api = APIRouter(tags=['acme:certificate'])


@api.post('/certificates/{serial_number}', response_class=Response, responses={
    200: {'content': {'application/pem-certificate-chain': {}}}
})
async def download_cert(
    response: Response, serial_number: constr(pattern='^[0-9A-F]+$'),
    data: Annotated[RequestData, Depends(SignedRequest())],
    accept: str = Header(default='*/*', pattern=r'(application/pem\-certificate\-chain|\*/\*)',
                         description='Certificates are only supported as "application/pem-certificate-chain"')
):
    async with db.transaction(readonly=True) as sql:
        pem_chain = await sql.value("""
            select cert.chain_pem from certificates cert
            join orders ord on cert.order_id = ord.id
            where cert.serial_number = $1 and ord.account_id = $2
        """, serial_number, data.account_id)
    if not pem_chain:
        raise ACMEException(status_code=status.HTTP_404_NOT_FOUND, type='malformed', detail='specified certificate not found for current account', new_nonce=data.new_nonce)
    return Response(content=pem_chain, headers=response.headers, media_type='application/pem-certificate-chain')


@api.post('/revoke-cert', response_class=Response)
async def revoke_cert(data: Annotated[RequestData[RevokeCertPayload], Depends(SignedRequest(RevokeCertPayload, allow_new_account=True))]):
    """
    https://www.rfc-editor.org/rfc/rfc8555#section-7.6
    """
    # this request might use account id or the account public key
    jwk_json: dict = data.key.export(as_dict=True)
    cert_bytes = base64url_decode(data.payload.certificate)
    cert = await parse_cert(cert_bytes)
    serial_number = SerialNumberConverter.int2hex(cert.serial_number)
    async with db.transaction(readonly=True) as sql:
        ok = await sql.value("""
            select true from certificates c
                join orders o on o.id = c.order_id
                join accounts a on a.id = o.account_id
            where
                c.serial_number = $1 and c.revoked_at is null and
                ($2::text is null or (a.id = $2::text and a.status='valid')) and a.jwk=$3
        """, serial_number, data.account_id, jwk_json)
    if not ok:
        raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, type='alreadyRevoked', detail='cert already revoked or not accessible', new_nonce=data.new_nonce)
    async with db.transaction(readonly=True) as sql:
        revocations = [(sn, rev_at) async for sn, rev_at in sql('select serial_number, revoked_at from certificates where revoked_at is not null')]
        revoked_at = await sql.value('select now()')
    revocations = set(revocations)
    revocations.add((serial_number, revoked_at))
    await ca_service.revoke_cert(serial_number=serial_number, revocations=revocations)
    async with db.transaction() as sql:
        await sql.exec("""
            update certificates set revoked_at = $2 where serial_number = $1 and revoked_at is null
        """, serial_number, revoked_at)
