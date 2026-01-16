# Some secrets may be passed as docker secrets:

## Database password:

Password from `DB_DSN` may be passed as `PGPASSFILE`. 

```yaml
# partial content
services:
  acme-ca-server:
    image: knrdl/acme-ca-server
    environment:
      DB_DSN: postgresql://postgres@db/postgres
      PGPASSFILE: /run/secrets/pg/pg.passfile
    secrets:
      - source: PG_PASSFILE
        target: /run/secrets/pg/pg.passfile
        uid: '1000'
        mode: 0o400
secrets:
  PG_PASSFILE:
    file: ./passfile.pg.secret
```

## Encryption key (and other variables)

Encryption key `CA_ENCRYPTION_KEY` may be passed as secret with name `/run/secrets/CA_ENCRYPTION_KEY`. `/entrypoint.sh` will create environment vars from first line of all files with `UPPERCASE_NAME` in `/run/secrets`.

```yaml
# partial content
services:
  acme-ca-server:
    image: knrdl/acme-ca-server
    environment:
      CA_ENCRYPTION_KEY: # will be imported from secret with entrypoint
    secrets:
      - source: CA_ENCRYPTION_KEY
        target: /run/secrets/CA_ENCRYPTION_KEY
        uid: '1000'
        mode: 0o400
secrets:
  CA_CHAIN_PEM:
    file: ./ca.pem
```

## CA Key and certificate

CA certificate and key may be passed as secrets to `/run/secrets/ca_import/` dir.

```yaml
# partial content
services:
  acme-ca-server:
    image: knrdl/acme-ca-server
    environment:
      CA_IMPORT_DIR: /run/secrets/ca_import
    secrets:
    - source: CA_KEY
      target: /run/secrets/ca_import/ca.key
      uid: '1000'
      mode: 0o400
    - source: CA_CHAIN_PEM
      target: /run/secrets/ca_import/ca.pem
      uid: '1000'
      mode: 0o444
secrets:
  CA_KEY:
    file: ./ca.key.secret
  CA_CHAIN_PEM:
    file: ./ca.pem
```