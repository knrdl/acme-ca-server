# ACME CA Server

[![Build](https://github.com/knrdl/acme-ca-server/actions/workflows/docker-image.yml/badge.svg)](https://github.com/knrdl/acme-ca-server/actions/workflows/docker-image.yml)

A self-hosted ACME server with a built-in CA and optional web interface.

## Features

* ✅ **ACME Server** implementation (supports `http-01` challenge)
* 🔐 **Built-in CA** to sign/revoke certificates (can be replaced with an external CA), CA rollover is supported
* ✉️ **Mail notifications**  (for account creation, expiring and expired certificates) with customizable templates
* 🌐 **Web UI** (certificate and domain log) with customizable templates

Tested with [Certbot](https://certbot.eff.org/), [Traefik](https://traefik.io/traefik/), [Caddy](https://caddyserver.com/), [uacme](https://github.com/ndilieto/uacme), [acme.sh](https://github.com/acmesh-official/acme.sh).

## Setup
### 1. Generate a new CA root certificate (or use an existing one)

You can generate a new root CA key and certificate using OpenSSL:

```shell
openssl genrsa -out ca.key 4096
openssl req -new -x509 -nodes -days 3650 -subj "/C=DE/O=Demo" -key ca.key -out ca.pem
````

These two files (`ca.key` and `ca.pem`) will be imported into the container on first startup.

> The container runs as a non-root user, so it must be able to read the key and certificate files.
> Make sure the permissions are set correctly:
>
> ```shell
> chmod 600 ca.key ca.pem  # protect key from other users
> chown 1000:1000 ca.key ca.pem  # ensures correct ownership
> ```

Once imported successfully, the CA data is stored in the database and you can remove the key files.


### 2. Deploy the container

Docker Compose snippet:

```yaml
services:

  acme-ca-server:
    image: knrdl/acme-ca-server
    restart: always
    environment:
      EXTERNAL_URL: https://acme.mydomain.org
      DB_DSN: postgresql://postgres:secret@db/postgres
    networks:
      - db_net
      - reverse_proxy_net
    volumes:
      - ./ca.key:/import/ca.key:ro # needed once to import new ca
      - ./ca.pem:/import/ca.pem:ro # needed once to import new ca
    mem_limit: 250m

  db:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_PASSWORD: secret  # use a strong password: `openssl rand -hex 32`
    networks:
      - db_net
    volumes:
      - ./db:/var/lib/postgresql/data
    mem_limit: 250m

networks:
  db_net:
  reverse_proxy_net:  # see next step
```

### 3. Reverse proxy

Serve the app securely using a TLS-terminating reverse proxy (like Apache, Nginx, Traefik or Caddy), e.g. at https://acme.mydomain.org

The app listens on port **8080** for HTTP traffic.

> For a quick test you can skip the reverse proxy and expose the service directly:
> ```yaml
> services:
>   acme-ca-server:
>     # ...
>     environment:
>       EXTERNAL_URL: http://localhost:8080
>     # ...
>     ports:
>       - "8080:8080"
>     # ...
> ```
> Don't do this in production. TLS usage is advised.

### 4. Test with certbot

```shell
docker run -it --rm certbot/certbot certonly --server https://acme.mydomain.org/acme/directory --standalone --no-eff-email --email user1@mydomain.org -v --domains test1.mydomain.org
```

## Customizations

### Environment Variables

| Env Var | Default | Description |
|---------|---------|-------------|
| EXTERNAL_URL        |         | The HTTPS address the server will be reachable from, e.g. https://acme.mydomain.org             |
| DB_DSN        |         | Postgres connection string, e.g. `postgresql://username:password@host/dbname` (the database will be initialized on startup)            |
| LOG_LEVEL | `info` | `debug`, `info`, `warning`, `error`  |
| ACME_TERMS_OF_SERVICE_URL        | `None`        | Optional URL which the ACME client can show when the user has to accept the terms of service, e.g. https://acme.mydomain.org/terms             |
| ACME_MAIL_REQUIRED        | `True`       | whether the user has to provide a mail address to obtain certificates via the ACME client (recommended)        |
| ACME_MAIL_TARGET_REGEX        | any mail address       | restrict the format of user-provided mail addresses. E.g. `[^@]+@mydomain\.org` only allows mail addresses from mydomain.org             |
| ACME_TARGET_DOMAIN_REGEX        | any non-wildcard domain name       | restrict the domain names for which certificates can be requested via ACME. E.g. `[^\*]+\.mydomain\.org` only allows domain names from mydomain.org             |
| CA_ENABLED        | `True`       | whether the internal CA is enabled, set this to false when providing a custom CA implementation  |
| CA_ENCRYPTION_KEY        | will be generated if not provided       | the key to protect the CA private keys at rest (encrypted in the database)  |
| CA_IMPORT_DIR        | `/import`       | where the *ca.pem* and *ca.key* are initially imported from, see 2. <br>CA rollover is as simple as placing a new cert and key in this directory. The server will detect and import them at startup. |
| CA_CERT_LIFETIME        | 60 days (`60d`)       | how often certs must be replaced by the ACME client  |
| CA_CERT_CDP_ENABLED    | `True` | Add CDP (Certificate Revocation List Distribution Point) URL to certificates, so clients SHOULD check certificates for revocation. When `False`, the CDP is omitted from certificates, preventing clients from checking revocation status and making revocation ineffective. |
| CA_CRL_LIFETIME        | 7 days (`7d`)       | how often the certificate revocation list will be rebuilt (despite rebuild on every certificate revocation)  |
| MAIL_ENABLED        | `False`       | if sending mails is enabled              |
| MAIL_HOST        | `None`       | SMTP host  |
| MAIL_PORT        | `None`       | SMTP port (default depends on encryption method)  |
| MAIL_USERNAME        | `None`       | SMTP auth username  |
| MAIL_PASSWORD        | `None`       | SMTP auth password  |
| MAIL_ENCRYPTION        | `tls`       | transport encryption method: `tls` (recommended), `starttls` or `plain` (unencrypted)  |
| MAIL_SENDER        | `None`       | the mail address shown when sending mails, e.g. `acme@mydomain.org`  |
| MAIL_NOTIFY_ON_ACCOUNT_CREATION        | `True`       | whether to send a mail when the user runs ACME for the first time  |
| MAIL_WARN_BEFORE_CERT_EXPIRES        | 20 days (`20d`)     | when to warn the user via mail that a certificate has not been renewed in time (can be disabled by providing `false` as value)  |
| MAIL_NOTIFY_WHEN_CERT_EXPIRED        | `True`       | whether to inform the user that a certificate finally expired which has not been renewed in time  |
| WEB_ENABLED        | `True` | whether to also provide UI endpoints or just the ACME functionality |
| WEB_ENABLE_PUBLIC_LOG        | `False` | whether to show a transparency log of all certificates generated via ACME  |
| WEB_APP_TITLE        | `ACME CA Server` | title shown in web and mails  |
| WEB_APP_DESCRIPTION        | `Self-hosted ACME CA Server` | description shown in web and mails  |

### Customize templates

#### Mail

Templates consist of `subject.txt` and `body.html` (see [here](./app/mail/templates)). Overwrite the following files:
* /app/mail/templates/**cert-expired-info**/{subject.txt,body.html}
* /app/mail/templates/**cert-expires-warning**/{subject.txt,body.html}
* /app/mail/templates/**new-account-info**/{subject.txt,body.html}

Template parameters:
* `app_title`: `str`  application title from `WEB_APP_TITLE`
* `app_desc`: `str`  application description from `WEB_APP_DESCRIPTION`
* `web_url`: `str`  web index url from `EXTERNAL_URL`
* `acme_url`: `str`  acme directory url
* `domains`: `list[str]` list of expiring domains
* `expires_at`: `datetime` domain expiration date
* `expires_in_days`: `int` days until cert will expire
* `serial_number`: `str` expiring certs serial number (hex)

#### Web UI

Custom files to be served by the http server can be placed in `/app/web/www`.

Overwrite templates (see [here](./app/web/templates)):
* /app/web/templates/cert-log.html (Certificate Listing)
* /app/web/templates/domain-log.html (Domain Listing)
* /app/web/templates/index.html (Startpage)

Template parameters:
* `app_title`: `str`  application title from `WEB_APP_TITLE`
* `app_desc`: `str`  application description from `WEB_APP_DESCRIPTION`
* `web_url`: `str`  web index url from `EXTERNAL_URL`
* `acme_url`: `str`  acme directory url
* `certs`: `list` list of certs for `cert-log.html`
* `domains`: `list` list of domains for `domain-log.html`

### Provide a custom CA implementation

First set env var `CA_ENABLED=False`. Then overwrite the file `/app/ca/service.py` (see [here](./app/ca/service.py)) in the docker image. It must provide two functions:

#### 1. `sign_csr()`

```python
async def sign_csr(csr: x509.CertificateSigningRequest, subject_domain: str, san_domains: list[str]) -> SignedCertInfo:
    ...
```

* `csr`: a [x509.CertificateSigningRequest](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.CertificateSigningRequest) object
* `subject_domain`: the main domain name for the certificate
* `san_domains`: *subject alternative names*, all domain names (including `subject_domain`) for the certificate
* *returns*: instance of `SignedCertInfo()`

```python
class SignedCertInfo:
    cert: x509.Certificate
    cert_chain_pem: str
```

* `cert`: a [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate) object
* `cert_chain_pem`: a PEM-encoded text file containing the created cert as well as the root or also intermediate cert. This file will be used by the ACME client

#### 2. `revoke_cert()`

```python
async def revoke_cert(serial_number: str, revocations: set[tuple[str, datetime]]) -> None:
    ...
```

* `serial_number`: certificate serial number to revoke as hex value
* `revocations`: all revoked certificates including the one specified by `serial_number`. It's a set of tuples containing `(serial_number, revocation_date)`
* *returns*: no error on success, throw exception otherwise

A custom CA backend must also handle the CRL (certificate revocation list) distribution.

## Internals

### Entities

```mermaid
flowchart LR
    accounts -->|1:0..n| orders
    orders -->|1:1..n| authorizations
    authorizations -->|1:1| challenges
    orders -->|1:0..1| certificates
```

### Tests

```shell
cd tests/e2e
./run.sh
cd ../pytest
./run.sh
cd coverage
python3 -m http.server  # coverage report at localhost:8000
```
