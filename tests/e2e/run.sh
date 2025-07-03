#!/bin/bash

# also works: alias docker='podman'

# cleanup
docker rm -f -v test_db
docker rm -f -v test_server
docker rm -f -v test_mail

docker network rm -f test_net

# run tests
set -e

docker build --pull -t acmeserver ../..

docker network create test_net

docker run -dit -e POSTGRES_PASSWORD=secret --name test_db --net test_net docker.io/postgres:16-alpine

docker run -dit --name test_mail --net test_net -p "3000:80" docker.io/rnwood/smtp4dev
echo See sent emails at http://localhost:3000

# generate ca key+cert
openssl genrsa -out ca.key 4096
openssl req -new -x509 -nodes -days 3650 -subj "/C=XX/O=Test" -key ca.key -out ca.pem -set_serial "0xDEADBEAF"
chmod a+r {ca.key,ca.pem}

function run_server() {
     docker run -dit --name test_server --net test_net -p8080:8080 --network-alias acme.example.org \
        -v "$PWD/ca.key:/import/ca.key:ro" -v "$PWD/ca.pem:/import/ca.pem:ro" \
        -e DB_DSN="postgresql://postgres:secret@test_db/postgres" \
        -e MAIL_ENABLED=true -e MAIL_HOST=test_mail -e MAIL_ENCRYPTION=plain -e MAIL_SENDER=acme@example.org \
        -e web_enable_public_log=true \
        -e EXTERNAL_URL="http://acme.example.org:8080" \
        -e CA_ENCRYPTION_KEY="DaxNj1bTiCsk6aQiY43hz2jDqBZAU5kta1uNBzp_yqo=" \
        acmeserver
}
run_server

sleep 5
curl --fail --silent localhost:8080 > /dev/null
curl --fail --silent localhost:8080/certificates > /dev/null
curl --fail --silent localhost:8080/endpoints > /dev/null

# certbot

rm -rf certbot
mkdir certbot

echo "Certbot 1a"
docker run --rm --pull always --name test_certbot1a --net test_net -v "$PWD/certbot:/etc/letsencrypt" \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot certonly \
     --server http://acme.example.org:8080/acme/directory --standalone --no-eff-email \
     --email certbot@example.org -vvv \
     --domains host1.example.org --domains host2.example.org

echo "Certbot 1b"
docker run --rm --name test_certbot1b --net test_net -v "$PWD/certbot:/etc/letsencrypt" \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot update_account --no-eff-email -m certbot2@example.org  \
     --server http://acme.example.org:8080/acme/directory

echo "Certbot 2"
docker run --rm --name test_certbot2 --net test_net -v "$PWD/certbot:/etc/letsencrypt" \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot certonly \
     --server http://acme.example.org:8080/acme/directory --standalone --no-eff-email --force-renewal \
     --email certbot@example.org -vvv \
     --domains host1.example.org --domains host2.example.org --domains host3.example.org

echo "Certbot 3a"
docker run --rm --name test_certbot3a --net test_net -v "$PWD/certbot:/etc/letsencrypt" \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot certificates \
     --server http://acme.example.org:8080/acme/directory

echo "Certbot 3b"
docker run --rm --name test_certbot3b --net test_net -v "$PWD/certbot:/etc/letsencrypt" \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot reconfigure \
     --server http://acme.example.org:8080/acme/directory --cert-name host1.example.org  -vvv

echo "Certbot 3c"
docker run --rm --name test_certbot3c --net test_net -v "$PWD/certbot:/etc/letsencrypt" \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot revoke \
     --server http://acme.example.org:8080/acme/directory --cert-name host1.example.org -vvv --non-interactive

echo "Certbot 3d"
docker run --rm --name test_certbot3d --net test_net -v "$PWD/certbot:/etc/letsencrypt" \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot certificates \
     --server http://acme.example.org:8080/acme/directory

echo "Certbot 4a"
docker run --rm --name test_certbot4a --net test_net -v "$PWD/certbot:/etc/letsencrypt" \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot show_account \
     --server http://acme.example.org:8080/acme/directory

echo "Certbot 4b"
docker run --rm --name test_certbot4b --net test_net -v "$PWD/certbot:/etc/letsencrypt" \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot unregister \
     --server http://acme.example.org:8080/acme/directory --non-interactive

echo "Certbot 4c"
docker run --rm --name test_certbot4c --net test_net -v "$PWD/certbot:/etc/letsencrypt" \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot show_account \
     --server http://acme.example.org:8080/acme/directory || true

echo "Certbot 5a (account without mail addr)"
docker run --rm --pull always --name test_certbot5a --net test_net \
     --network-alias host1.example.org --network-alias host2.example.org --network-alias host3.example.org docker.io/certbot/certbot certonly \
     --server http://acme.example.org:8080/acme/directory --standalone --no-eff-email \
     -vvv \
     --domains host1.example.org --domains host2.example.org 2>&1 | grep urn:ietf:params:acme:error:malformed


# Traefik

rm -rf traefikdata
mkdir traefikdata

echo "Traefik 1"
docker run -dit --rm --pull always --name test_traefik --net test_net -v "$PWD/traefik.yaml:/file.yaml:ro" -v "$PWD/traefikdata:/acme" -p8082:80 -p8083:8080 \
        --network-alias host20.example.org docker.io/traefik:latest --log.level=DEBUG --providers.file.filename=/file.yaml --api.insecure=true --api.dashboard=true \
        --entrypoints.web.address=:80 --entrypoints.web-secure.address=:443 \
          --certificatesresolvers.myresolver.acme.email=traefik@example.org \
          --certificatesresolvers.myresolver.acme.storage=/acme/acme.json \
          --certificatesresolvers.myresolver.acme.httpChallenge.entryPoint=web \
          --certificatesresolvers.myresolver.acme.caServer=http://acme.example.org:8080/acme/directory

while true; do
        cat traefikdata/acme.json | jq '.myresolver.Certificates[0].domain.main == "host20.example.org"' | grep 'true' && break
        sleep 1
done

docker kill test_traefik

# Caddy

rm -rf caddydata
mkdir caddydata

echo "Caddy 1"
docker run -dit --rm --pull always --name test_caddy --net test_net -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$PWD/caddydata:/data" \
     --network-alias host10.example.org docker.io/caddy:alpine

while [ ! -f ./caddydata/caddy/certificates/localhost-8080-acme-directory/host10.example.org/host10.example.org.crt ]; do
  sleep 1
done

docker kill test_caddy

# uacme

rm -rf uacmedata
mkdir uacmedata

docker build --pull -t uacme -f Dockerfile.uacme .

echo "uacme 1"
docker run --rm --name test_uacme1 --net test_net -v "$PWD/uacmedata:/uacme" \
     uacme uacme -v -c /uacme \
     --acme-url http://acme.example.org:8080/acme/directory new uacme@example.org

echo "uacme 2"
docker run --rm --name test_uacme2 --net test_net -v "$PWD/uacmedata:/uacme" \
     --network-alias host30.example.org -e UACME_CHALLENGE_PATH=/var/www/html/.well-known/acme-challenge uacme \
     bash -c "nginx -g 'daemon on;' && uacme -vvv -c /uacme -h /usr/share/uacme/uacme.sh \
     --acme-url http://acme.example.org:8080/acme/directory issue host30.example.org"

echo "uacme 3 (missing email addr on account registration)"
docker run --rm --name test_uacme1 --net test_net \
     uacme uacme -v -y -c /tmp \
     --acme-url http://acme.example.org:8080/acme/directory new 2>&1 | grep urn:ietf:params:acme:error:malformed

# acme.sh

rm -rf acmeshdata
mkdir acmeshdata

echo "acme.sh 1"
docker run --rm --name test_acmesh1 --net test_net -v "$PWD/acmeshdata:/acme.sh" --network-alias host40.example.org \
     docker.io/neilpang/acme.sh --issue -d host40.example.org --standalone \
     --accountemail acmesh@example.org --server http://acme.example.org:8080/acme/directory

echo "acme.sh 2"
docker run --rm --name test_acmesh2 --net test_net -v "$PWD/acmeshdata:/acme.sh" --network-alias host40.example.org \
     docker.io/neilpang/acme.sh --revoke -d host40.example.org --server http://acme.example.org:8080/acme/directory



docker kill test_server
docker logs test_server
docker rm test_server

docker exec test_db psql -U postgres -c "update certificates set not_valid_before=now() - interval '50 day', not_valid_after=now() - interval '10 days' where order_id = (select id from orders where status = 'valid' order by id asc limit 1);"
docker exec test_db psql -U postgres -c "update certificates set not_valid_before=now() - interval '50 day', not_valid_after=now() + interval '10 days' where order_id = (select id from orders where status = 'valid' order by id desc limit 1);"

run_server

sleep 5

docker kill test_server

docker logs test_server