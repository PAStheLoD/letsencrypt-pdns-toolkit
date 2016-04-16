#!/bin/bash

cd $(dirname $(readlink -f $0))

if [[ ! -r cert.pem ]] || [[ ! -r key.pem ]] ; then
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days XXX -subj '/CN=le-crypt' -nodes
fi

uwsgi --http 0.0.0.0:8888 --https 0.0.0.0:8443,cert.pem,key.pem  --threads 2 -w le-api:app --set-ph config-file=le-config.json
