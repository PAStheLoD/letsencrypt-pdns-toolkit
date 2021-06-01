#!/bin/bash

cd $(dirname $(readlink -f $0))

CERT_FILE=cert.pem
KEY_FILE=cert.key

if type -P openssl &> /dev/null ; then
    OPENSSL_AVAILABLE=yes
fi


if [[ ! -r "$CERT_FILE" ]] || [[ ! -r "$KEY_FILE" ]] ; then
    if [[ "$OPENSSL_AVAILABLE" != "yes" ]] ; then
        echo "FATAL: OpenSSL CLI unavailable, cannot generate key and self-signed certificate."
        exit 1
    fi

    openssl req -x509 -newkey ed25519 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 720 -subj '/CN=le-crypt' -nodes || { echo "Error while generating server keypair/cert"; exit 1; }
fi

export PATH=$(readlink -f ./venv/bin):$PATH

uwsgi=$(type -P uwsgi 2>/dev/null)

if [[ "$uwsgi" = "" ]] || [[ ! -x "$uwsgi" ]] ; then
    echo "Cannot found working uwsgi"
    exit 1
fi


if [[ "$OPENSSL_AVAILABLE" = "yes" ]] ; then

    FP=$(openssl x509 -fingerprint -sha256 -noout -in "$CERT_FILE")

    echo "

    * * * verify this on the client * * *

    FP = $FP

    echo | openssl s_client -connect your-server.internetz:8443 2>/dev/null | openssl x509 -fingerprint -sha256 -noout

    $FP

    * * *

    "
fi

exec uwsgi --need-app --http 0.0.0.0:8888 --https 0.0.0.0:8443,$CERT_FILE,$KEY_FILE --threads 2 -w le-api:app --set-ph config-file=le-config.json --touch-reload le-config.json --set-ph log-level=debug
