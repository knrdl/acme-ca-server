from pathlib import Path
import db
from logger import logger


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
            cur_level = await sql.value('select migration from migrations')
            next_level = cur_level + 1
            cur_file = Path('db/migrations') / f'{cur_level:0>3}.sql'
            next_file = Path('db/migrations') / f'{next_level:0>3}.sql'
            if not next_file.is_file():
                break
            logger.info(f'Running migration: {next_file.name}')
            with open(next_file) as f:
                await sql.exec(f.read())
            await sql.exec('update migrations set migration=$1', next_level)
            dirty = True
        if dirty:
            logger.info(
                f'Finished database migrations (current level: {cur_file.name})')
        else:
            logger.info(
                f'Database migrations are up to date (current level: {cur_file.name})')
