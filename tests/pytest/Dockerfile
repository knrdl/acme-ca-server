FROM python:3.12.7-alpine

RUN apk add openssl

RUN pip install pytest

WORKDIR /runner

COPY pyproject.toml .

COPY requirements.txt ./

RUN pip install -r ./requirements.txt

COPY app ./app/

COPY tests/pytest ./tests/pytest/

CMD [ "pytest", "." ]
