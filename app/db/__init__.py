import json
from typing import Any

import asyncpg
from pydantic import BaseModel

from config import settings
from logger import logger

_pool: asyncpg.pool.Pool


async def connect():
    global _pool
    _pool = await asyncpg.create_pool(
        min_size=0, max_size=20, dsn=settings.db_dsn, init=init_connection, server_settings={"application_name": settings.web.app_title})


async def disconnect():
    global _pool
    await _pool.close()

async def init_connection(conn: asyncpg.Connection):
    await conn.set_type_codec('jsonb', encoder=_encode_json, decoder=json.loads, schema='pg_catalog')


def _encode_json(payload: Any) -> str:
    if isinstance(payload, BaseModel):
        return payload.json()
    else:
        return json.dumps(payload)


class transaction:
    readonly = False

    def __init__(self, readonly=False) -> None:
        self.readonly = readonly

    async def __aenter__(self, *args, **kwargs):
        self.conn: asyncpg.Connection = await _pool.acquire()
        self.trans: asyncpg.connection.transaction = self.conn.transaction(readonly=self.readonly)
        await self.trans.start()
        return self

    async def __call__(self, *args):
        """fetch response for query"""
        async for rec in self.conn.cursor(*args):
            yield rec

    async def record(self, *args):
        """fetch first response row for query"""
        return await self.conn.fetchrow(*args)

    async def value(self, *args):
        """fetch first value from frist response row for query"""
        return await self.conn.fetchval(*args)

    async def exec(self, *args):
        """execute command"""
        return await self.conn.execute(*args)

    async def execmany(self, command: str, *args):
        """execute command with many records"""
        return await self.conn.executemany(command, args)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            logger.debug('Transaction rollback. Reason: %s %s', exc_type, exc_val, exc_tb)
            await self.trans.rollback()
        else:
            await self.trans.commit()
        await _pool.release(self.conn)
