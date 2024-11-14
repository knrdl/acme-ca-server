from app.constants import MIGRATIONS_PATH

from ... import db
from ...logger import logger


async def run():
    async with db.transaction() as sql:
        await sql.exec("""
            create table if not exists migrations (
                dummy_id integer unique default 1 check (dummy_id = 1), -- there should only be one row
                migration int not null default 0,
                migrated_at timestamptz not null default now()
            );
            insert into migrations (migration) values (default) on conflict do nothing;
        """)

        dirty = False

        while True:
            cur_level = await sql.value("""select migration from migrations""")
            next_level = cur_level + 1

            # These paths dont' work for testing. Let's define an absolute path
            cur_file = MIGRATIONS_PATH / f'{cur_level:0>3}.sql'
            next_file = MIGRATIONS_PATH / f'{next_level:0>3}.sql'
            if not next_file.is_file():
                break
            logger.info('Running migration: %s', next_file.name)
            with open(next_file, encoding='utf-8') as f:
                await sql.exec(f.read())
            await sql.exec("""update migrations set migration=$1""", next_level)
            dirty = True
        if dirty:
            logger.info(
                'Finished database migrations (current level: %s)', cur_file.name
            )
        else:
            logger.info(
                'Database migrations are up to date (current level: %s)', cur_file.name
            )
