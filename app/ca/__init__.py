import asyncio

import db
from acme.certificate.service import SerialNumberConverter
from config import settings
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Response
from logger import logger
from pydantic import constr

router = APIRouter(prefix='/ca', tags=['ca'])

if settings.ca.enabled:
    from cryptography.fernet import Fernet  # pylint: disable=ungrouped-imports

    from . import cronjob
    from .service import build_crl_sync

    @router.get('/{serial_number}/crl', response_class=Response, responses={200: {'content': {'application/pkix-crl': {}}}})
    async def download_crl(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
        async with db.transaction(readonly=True) as sql:
            crl_pem = await sql.value("""select crl_pem from cas where serial_number = $1""", serial_number)
        return Response(content=crl_pem, media_type='application/pkix-crl')

    async def init():
        if (settings.ca.import_dir / 'ca.pem').is_file() and (settings.ca.import_dir / 'ca.key').is_file():
            with open(settings.ca.import_dir / 'ca.key', 'rb') as f:
                ca_key_bytes = f.read()
            ca_key = serialization.load_pem_private_key(ca_key_bytes, None)
            f = Fernet(settings.ca.encryption_key.get_secret_value())
            ca_key_enc = f.encrypt(ca_key_bytes)

            with open(settings.ca.import_dir / 'ca.pem', 'rb') as f:
                ca_cert_bytes = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes, None)
            serial_number = SerialNumberConverter.int2hex(ca_cert.serial_number)

            async with db.transaction(readonly=True) as sql:
                revocations = [record async for record in sql("""select serial_number, revoked_at from certificates where revoked_at is not null""")]
            _, crl_pem = await asyncio.to_thread(build_crl_sync, ca_key=ca_key, ca_cert=ca_cert, revocations=revocations)

            async with db.transaction() as sql:
                await sql.exec("""update cas set active = false""")
                await sql.exec(
                    """
                    insert into cas (serial_number, cert_pem, key_pem_enc, active, crl_pem)
                        values ($1, $2, $3, true, $4)
                    on conflict (serial_number) do update set active = true, crl_pem = $4
                    """,
                    serial_number,
                    ca_cert_bytes.decode(),
                    ca_key_enc,
                    crl_pem,
                )
            logger.info('Successfully imported CA provided in "%s" folder', settings.ca.import_dir)
        else:
            async with db.transaction() as sql:
                ok = await sql.value("""select count(serial_number)=1 from cas where active=true""")
            if not ok:
                raise ValueError('internal ca is enabled but no CA certificate is registered and active. Please import one first.')

        await cronjob.start()
else:

    async def init():
        logger.info('Builtin CA is disabled, relying on custom CA implementation')
