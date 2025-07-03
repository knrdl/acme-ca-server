FROM python:3.13.5-alpine

RUN apk add openssl

RUN pip install pytest coverage

WORKDIR /runner

COPY pyproject.toml .

COPY requirements.txt ./

RUN pip install -r ./requirements.txt

COPY app ./app/

COPY tests/pytest ./tests/pytest/

CMD coverage run --branch -m pytest && coverage html --omit="./tests/*"