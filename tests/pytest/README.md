
# PyTest

## Run without docker

1. Start a new (pristine) postgres db instance
2. Install project dependencies: `pip install -r requirements.txt`
3. Install pytest: `pip install pytest`
4. In project root directory, run tests like this: `db_dsn=postgresql://postgres:postgres@localhost/postgres pytest .`

## Run with docker

execute `./run.sh`