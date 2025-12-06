FROM docker.io/python:3.14.1-alpine3.23

RUN apk add openssl

RUN pip install pytest coverage

WORKDIR /runner

COPY pyproject.toml .

COPY requirements.txt ./

RUN pip install -r ./requirements.txt

COPY app ./app/

COPY tests/pytest ./tests/pytest/

CMD coverage run --branch -m pytest && coverage html --omit="./tests/*"