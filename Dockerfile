FROM docker.io/python:3.12.7-alpine

RUN adduser --no-create-home --disabled-password appuser && \
    apk update --no-cache

EXPOSE 8080/tcp
ENV PYTHONUNBUFFERED=True

COPY app /app
RUN pip install --no-cache-dir --upgrade -r app/requirements.txt

ADD --chmod=0644 https://cdnjs.cloudflare.com/ajax/libs/milligram/1.4.1/milligram.min.css /app/web/www/libs/
ADD --chmod=0644 https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js /app/web/www/libs/
ADD --chmod=0644 https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css /app/web/www/libs/

USER appuser
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]

HEALTHCHECK --start-period=10s --interval=3m --timeout=1s \
  CMD wget --quiet --spider http://127.0.0.1:8080/acme/directory || exit 1
