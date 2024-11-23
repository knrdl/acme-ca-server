#!/bin/bash

# also works: alias docker='podman'

docker network rm -f test_net

docker container rm -f test_db

set -e

docker build --pull -t testrunner -f ./Dockerfile ../..

docker network create test_net

docker run -dt -e POSTGRES_PASSWORD=secret --name test_db --net test_net docker.io/postgres:16-alpine

docker run -t --rm --name test_runner --net test_net -e db_dsn=postgresql://postgres:secret@test_db/postgres testrunner
