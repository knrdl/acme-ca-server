# ACME CA Server

# Features

* **ACME Server** implementation (http-01 challenge)
* **Builtin CA** to sign/revoke certificates (can be replaced with an external CA), CA rollover is supported
* Notification **Mails** (account created, certificate will expire soon, certificate is expired) with customizable templates
* **Web UI** (certificate log) with customizable templates

# Setup

## 1. Generate a CA root certificate (or use an existing cert)

```
$ openssl genrsa -out ca.key 4096
$ openssl req -new -x509 -nodes -days 3650 -subj "/C=TestCA/O=Demo" -key ca.key -out ca.pem
```

## 2. Deploy the container

```yaml
version: '2.4'
services:

  acme-ca-server:
    image: knrdl/acme-ca-server
    restart: always
    environment:
      EXTERNAL_URI: http://localhost:8080
      DB_DSN: postgresql://postgres:secret@db/postgres
    # ports:
    #   - "8080:8080"
    networks:
      - net
    volumes:
      - ./ca.key:/import/ca.key:ro # needed once to import new ca
      - ./ca.pem:/import/ca.pem:ro # needed once to import new ca
    mem_limit: 250m

  db:
    image: postgres:15-alpine
    restart: always
    environment:
      POSTGRES_PASSWORD: secret
    networks:
      - net
    volumes:
      - ./db:/var/lib/postgresql/data
    mem_limit: 250m

networks:
  net:
```

## 3. Reverse proxy

Serve the app behind a TLS terminating reverse proxy, e.g. as https://acme.mydomain.org

The app listens on port 8080 for http traffic.

## 4. Test with certbot

```shell
docker run -it --rm certbot/certbot certonly --server https://acme.mydomain.org/acme/directory --standalone --no-eff-email --email user1@mydomain.org -v --domains test1.mydomain.org
```

# Customizations

## Environment Variables

| Env Var | Default | Description |
|---------|---------|-------------|
| EXTERNAL_URI        |         | The HTTPS address the server will be reachable from, e.g. https://acme.mydomain.org             |
| DB_DSN        |         | Postgres connection string, e.g. postgresql://username:password@host/dbname (database will be initialized on startup)            |
| ACME_TERMS_OF_SERVICE_URL        | `None`        | Optional URL which the ACME client can show when the user has to accept the terms of service, e.g. https://acme.mydomain.org/terms             |
| ACME_MAIL_TARGET_REGEX        | any mail address       | restrict the email address which must be provided to the ACME client by the user. E.g. `[^@]+@mydomain\.org` only allows mail addresses from mydomain.org             |
| ACME_TARGET_DOMAIN_REGEX        | any non-wildcard domain name       | restrict the domain names for which certificates can be requested via ACME. E.g. `[^\*]+\.mydomain\.org` only allows domain names from mydomain.org             |
| CA_ENABLED        | `True`       | whether the internal CA is enabled, set this to false when providing a custom CA implementation  |
| CA_CERT_LIFETIME        | 60 days (`60 00:00`)       | how often certs will be replaced by the ACME client  |
| CA_CRL_LIFETIME        | 7 days (`7 00:00`)       | how often the certificate revocation list will be rebuilt  |
| CA_ENCRYPTION_KEY        | will be generated if not provided       | the key to protect the CA private keys on rest (when stored in db)  |
| MAIL_ENABLED        | `False`       | if sending emails is enabled              |
| MAIL_HOST        | `None`       | smtp host  |
| MAIL_PORT        | `None`       | smtp port (default depends on encryption method)  |
| MAIL_USERNAME        | `None`       | smtp auth username  |
| MAIL_PASSWORD        | `None`       | smtp auth password  |
| MAIL_ENCRYPTION        | `tls`       | transport encryption method: `tls` (recommended), `starttls` or `plain` (unencrypted)  |
| MAIL_SENDER        | `None`       | the email address shown when sending mails, e.g. `acme@mydomain.org`  |
| MAIL_NOTIFY_ON_ACCOUNT_CREATION        | `True`       | whether to send a mail when the user runs ACME for the first time  |
| MAIL_WARN_BEFORE_CERT_EXPIRES        | 20 days (`20 00:00`)     | when to warn the user via mail that a certificate has not been renewed in time (can be disabled by providing `false` as value)  |
| MAIL_NOTIFY_WHEN_CERT_EXPIRED        | `True`       | whether to inform the user that a certificate finally expired which has not been renewed in time  |
| WEB_ENABLED        | `True` | whether to also provide UI endpoints or just the ACME functionality |
| WEB_ENABLE_PUBLIC_CERT_LOG        | `False` | whether to show a transparency log of all certificates generated via ACME  |
| WEB_APP_TITLE        | `ACME CA Server` | title shown in web and mails  |
| WEB_APP_DESCRIPTION        | `Self hosted ACME CA Server` | description shown in web and mails  |

## Customize templates

### Mail

Templates consist of `subject.txt` and `body.html`:
* /app/mail/templates/**cert-expired-info**/{subject.txt,body.html}
* /app/mail/templates/**cert-expires-warning**/{subject.txt,body.html}
* /app/mail/templates/**new-account-info**/{subject.txt,body.html}

Parameters:
* `app_title`: `str`  application title from `WEB_APP_TITLE`
* `app_desc`: `str`  application description from `WEB_APP_DESCRIPTION`
* `domains`: `list[str]` list of expiring domains
* `expires_at`: `datetime` domain expiration date
* `serial_number`: `str` expiring certs serial number (hex)

### Web UI

Custom files to be served by the http server can be placed in `/app/web/www`.

Overwrite templates:
* /app/web/templates/cert-log.html
* /app/web/templates/index.html

## Provide a custom CA implementation

First set env var `CA_ENABLED=False`. Then overwrite the file `/app/ca/service.py` in the docker image. It must provide two functions:

### 1. `sign_csr()`

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

### 2. `revoke_cert()`

```python
async def revoke_cert(serial_number: str, revocations: set[tuple[str, datetime]]) -> None:
    ...
```

* serial_number: certificate serial number to revoke as hex value
* revocations: all revoked certificates including the one specified by `serial_number`. It's a set of tuples containing `(serial_number, revocation_date)`
* *returns*: no error on success

A custom CA backend must also handle the CRL (certificate revocation list) distribution.

# Internals

## Entities

```mermaid
flowchart TD
    accounts -->|1:0..n| orders
    orders -->|1:1..n| authorizations
    authorizations -->|1:1| challenges
    orders -->|1:0..1| certificates
```