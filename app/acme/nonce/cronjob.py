import asyncio

from logger import logger

import db


async def start():
    async def run():
        while True:
            try:
                async with db.transaction() as sql:
                    await sql.exec("""delete from nonces where expires_at < now()""")
            except Exception:
                logger.error('could not purge old nonces', exc_info=True)
            finally:
                await asyncio.sleep(1 * 60 * 60)

    asyncio.create_task(run())
