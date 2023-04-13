import asyncio
from .service import build_crl_sync, load_ca_sync
from logger import logger

import db


async def start():
    async def run():
        while True:
            try:
                async with db.transaction(readonly=True) as sql:
                    cas = [record async for record in sql('select serial_number, cert_pem, key_pem_enc from cas')]
                for sn, cert_pem, key_pem_enc in cas:
                    ca_cert, ca_key = await asyncio.to_thread(load_ca_sync, cert_pem=cert_pem, key_pem_enc=key_pem_enc)
                    async with db.transaction(readonly=True) as sql:  # todo: maybe also include expired certs
                        revocations = [record async for record in sql("select serial_number, revoked_at from certificates where revoked_at is not null") ]
                    crl, crl_pem = await asyncio.to_thread(build_crl_sync, ca_key=ca_key, ca_cert=ca_cert, revocations=revocations)
                    async with db.transaction() as sql:
                        await sql.exec("update cas set crl_pem = $1 where serial_number = $2", crl_pem, sn)
            except:
                logger.error('could not rebuild crl', exc_info=True)
            finally:
                await asyncio.sleep(12*60*60)  # rebuild crl every 12h
    asyncio.create_task(run())