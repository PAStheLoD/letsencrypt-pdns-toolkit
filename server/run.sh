#!/bin/bash

cd $(dirname $(readlink -f $0))

if [[ ! -r cert.pem ]] || [[ ! -r cert.key ]] ; then
    openssl req -x509 -newkey rsa:2048 -keyout cert.key -out cert.pem -days 720 -subj '/CN=le-crypt' -nodes || { echo "Error while generating server keypair/cert"; exit 1; }
fi

export PATH=$(readlink -f ./venv/bin):$PATH

uwsgi=$(which uwsgi 2>/dev/null)

if [[ "$uwsgi" = "" ]] || [[ ! -x "$uwsgi" ]] ; then
    echo "Cannot found working uwsgi"
    exit 1
fi

exec uwsgi --need-app --http 0.0.0.0:8888 --https 0.0.0.0:8443,cert.pem,cert.key --threads 2 -w le-api:app --set-ph config-file=le-config.json --touch-reload le-config.json --set-ph log-level=debug
