FROM docker.io/python:3.15.0a2-alpine3.23

RUN adduser --no-create-home --disabled-password appuser && \
    apk update --no-cache

WORKDIR /app
EXPOSE 8080/tcp
ENV PYTHONUNBUFFERED=True

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY app /app

RUN mkdir -p /app/web/www/libs/

ADD --chmod=0644 https://cdnjs.cloudflare.com/ajax/libs/milligram/1.4.1/milligram.min.css /app/web/www/libs/milligram.min.css
ADD --chmod=0644 https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js /app/web/www/libs/swagger-ui-bundle.js
ADD --chmod=0644 https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css /app/web/www/libs/swagger-ui.css

# precompile python files for faster startups
RUN python3 -m compileall .

USER appuser
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]

HEALTHCHECK --start-period=10s --interval=3m --timeout=1s \
  CMD wget --quiet --spider http://127.0.0.1:8080/acme/directory || exit 1
