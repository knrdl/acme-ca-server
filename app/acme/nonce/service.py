import secrets

import db
from fastapi import status

from ..exceptions import ACMEException


async def generate() -> str:
    nonce = secrets.token_urlsafe(32)
    async with db.transaction() as sql:
        await sql.exec("""insert into nonces (id) values ($1)""", nonce)
    return nonce


async def refresh(nonce: str) -> str:
    new_nonce = secrets.token_urlsafe(32)
    async with db.transaction() as sql:
        old_nonce_ok = await sql.exec("""delete from nonces where id = $1""", nonce) == 'DELETE 1'
        await sql.exec("""insert into nonces (id) values ($1)""", new_nonce)
    if not old_nonce_ok:
        raise ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='badNonce', detail='old nonce is wrong', new_nonce=new_nonce)
    return new_nonce
