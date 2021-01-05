#!/bin/bash

cd $(dirname $(readlink -f $0))

CERT_FILE=cert.pem
KEY_FILE=cert.key

if [[ ! -r "$CERT_FILE" ]] || [[ ! -r "$KEY_FILE" ]] ; then
    openssl req -x509 -newkey ed25519 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 720 -subj '/CN=le-crypt' -nodes || { echo "Error while generating server keypair/cert"; exit 1; }
fi

export PATH=$(readlink -f ./venv/bin):$PATH

uwsgi=$(which uwsgi 2>/dev/null)

if [[ "$uwsgi" = "" ]] || [[ ! -x "$uwsgi" ]] ; then
    echo "Cannot found working uwsgi"
    exit 1
fi

exec uwsgi --need-app --http 0.0.0.0:8888 --https 0.0.0.0:8443,$CERT_FILE,$KEY_FILE --threads 2 -w le-api:app --set-ph config-file=le-config.json --touch-reload le-config.json --set-ph log-level=debug
