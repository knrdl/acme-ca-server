FROM python:3.12.7-alpine

RUN apk add openssl

RUN pip install pytest

WORKDIR /runner

COPY pyproject.toml .

COPY requirements.txt ./app/

RUN pip install -r ./app/requirements.txt

COPY app ./app/

COPY tests/pytest ./tests/pytest/

CMD [ "pytest", "." ]
