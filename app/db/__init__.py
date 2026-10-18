import json
from collections.abc import AsyncGenerator
from typing import Any

import asyncpg
from config import settings
from logger import logger
from pydantic import BaseModel

_POOL: asyncpg.pool.Pool | None = None


async def connect():
    global _POOL  # pylint: disable=global-statement
    _POOL = await asyncpg.create_pool(min_size=0, max_size=20, dsn=str(settings.db_dsn), init=init_connection, server_settings={'application_name': settings.web.app_title})


async def disconnect():
    if _POOL is not None:
        await _POOL.close()


async def init_connection(conn: asyncpg.Connection):
    await conn.set_type_codec('jsonb', encoder=_encode_json, decoder=json.loads, schema='pg_catalog')


def _encode_json(payload: Any) -> str:
    if isinstance(payload, BaseModel):
        return payload.json()
    else:
        return json.dumps(payload)


class transaction:  # pylint: disable=invalid-name
    readonly = False

    def __init__(self, readonly: bool = False) -> None:
        self.readonly = readonly
        self.conn: asyncpg.Connection
        self.trans: asyncpg.connection.transaction

    async def __aenter__(self) -> transaction:
        if not _POOL:
            raise RuntimeError('database pool not initialized')
        self.conn = await _POOL.acquire()
        self.trans = self.conn.transaction(readonly=self.readonly)
        await self.trans.start()
        return self

    async def __call__(self, *args) -> AsyncGenerator[Any, None]:
        """fetch response for query"""
        async for rec in self.conn.cursor(*args):
            yield rec

    async def record(self, *args):
        """fetch first response row for query"""
        return await self.conn.fetchrow(*args)

    async def value(self, *args):
        """fetch first value from first response row for query"""
        return await self.conn.fetchval(*args)

    async def exec(self, *args):  # noqa: A003 (allow shadowing builtin "type")
        """execute command"""
        return await self.conn.execute(*args)

    async def execmany(self, command: str, *args):
        """execute command with many records"""
        return await self.conn.executemany(command, args)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            logger.debug('Transaction rollback. Reason: %s %s %s', exc_type, exc_val, exc_tb)
            await self.trans.rollback()
        else:
            await self.trans.commit()
        await _POOL.release(self.conn)
