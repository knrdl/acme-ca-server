import asyncio

import db
import mail
from config import settings
from logger import logger


async def start():
    async def run():
        while True:
            try:
                async with db.transaction(readonly=True) as sql:
                    results = [
                        record
                        async for record in sql(
                            """
                            with
                                expiring_domains as (
                                    select authz.domain, acc.mail, cert.serial_number, cert.not_valid_after from certificates cert
                                        join orders ord on cert.order_id = ord.id
                                        join accounts acc on ord.account_id = acc.id
                                        join authorizations authz on authz.order_id = ord.id
                                    where acc.status = 'valid' and ord.status = 'valid' and cert.revoked_at is null and (
                                        ($1::interval is not null and cert.not_valid_after > now() and cert.not_valid_after < now()+$1 and not cert.user_informed_cert_will_expire)
                                        or
                                        (cert.not_valid_after < now() and not cert.user_informed_cert_has_expired)
                                    )
                                    order by authz.domain
                                ),
                                newest_domains as (
                                    select authz.domain, max(cert.not_valid_after) as not_valid_after from orders ord
                                        join authorizations authz on authz.order_id = ord.id
                                        join certificates cert on cert.order_id = ord.id
                                        join expiring_domains exp on exp.domain = authz.domain
                                    group by authz.domain
                                )
                            select expd.mail, expd.serial_number, expd.not_valid_after, expd.not_valid_after < now() as is_expired, array_agg(expd.domain) as domains
                                from expiring_domains expd
                                join newest_domains newd on expd.domain = newd.domain and expd.not_valid_after = newd.not_valid_after
                            group by expd.mail, expd.serial_number, expd.not_valid_after
                                having array_length(array_agg(expd.domain), 1) > 0
                            """,
                            settings.mail.warn_before_cert_expires,
                        )
                    ]
                for mail_addr, serial_number, expires_at, is_expired, domains in results:
                    if not is_expired and settings.mail.warn_before_cert_expires:
                        try:
                            await mail.send_certs_will_expire_warn_mail(receiver=mail_addr, domains=domains, expires_at=expires_at, serial_number=serial_number)
                            ok = True
                        except Exception:
                            logger.error('could not send_certs_will_expire_warn_mail for "%s"', mail_addr, exc_info=True)
                            ok = False
                        if ok:
                            async with db.transaction() as sql:
                                await sql.exec("""update certificates set user_informed_cert_will_expire=true where serial_number=$1""", serial_number)
                    if is_expired and settings.mail.notify_when_cert_expired:
                        try:
                            await mail.send_certs_expired_info_mail(receiver=mail_addr, domains=domains, expires_at=expires_at, serial_number=serial_number)
                            ok = True
                        except Exception:
                            logger.error('could not send_certs_expired_info_mail for "%s"', mail_addr, exc_info=True)
                            ok = False
                        if ok:
                            async with db.transaction() as sql:
                                await sql.exec("""update certificates set user_informed_cert_has_expired=true where serial_number=$1""", serial_number)
            except Exception:
                logger.error('could not inform about expiring certificates', exc_info=True)
            finally:
                await asyncio.sleep(1 * 60 * 60)

    if settings.mail.notify_when_cert_expired or settings.mail.warn_before_cert_expires:
        asyncio.create_task(run())
