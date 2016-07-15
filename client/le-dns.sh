#!/bin/bash

# based on @antoifon's script
# https://github.com/antoiner77/letsencrypt.sh-pdns/blob/master/pdns.sh
#

set -e
set -u
set -o pipefail
umask 077



if [[ ! -r le.config ]] ; then
    echo "Missing le.config"
    exit 1
fi


if [[ $(grep -Po 'api_server=' le.config) != "api_server=" ]] ; then
    echo "API Server not configured (missing api_server="..." from le.config)"
    exit 1
fi

api_server=$(grep -Po 'api_server="\K[^"]+(?=")' le.config)


api_server_cert="$(grep -Po 'api_server_cert="\K[^"]+(?=")' le.config)"

if [[ "$api_server_cert" != "" ]] ; then
    if [[ -r "$api_server_cert" ]] ; then
        ca="--cacert \"$api_server_cert\""
        scheme="https"
    else
        echo "api_server_cert is set but not readable"
        exit 1
    fi
else
    scheme="http"
    ca=""
fi

echo "DEBUG: args: $@"

if [[ ! "$#" -gt 3 ]] ; then
    echo "usage: ./$0 [mode] [domain] \"\" [token!]"
    exit 0
fi

domain="${2}"
token="${4}"
timestamp=$(date +%s)

if [[ $(grep -Po "domain=\"$domain\"" le.config | wc -l) != 1 ]] ; then
    echo "domain=\"$domain\" must be configured in le.config"
    exit 1
fi

key="$(grep -Po "domain=\"$domain\"\s+key=\"\K[^\"]+(?=\")" le.config)"

done="no"

if [[ "$1" = "deploy_challenge" ]]; then
  curl "${scheme}://${api_server}/api/_acme-challenge.${domain}" $ca -d "$token" -H "API-Key: $key"

  while ! dig +trace @8.8.8.8 -t TXT "_acme-challenge.${domain}" | grep -- "$token" > /dev/null
    do
       printf "."
       sleep 3
    done
   done="yes"
fi

if [[ "$1" = "clean_challenge" ]]; then
    curl -X DELETE "${scheme}://${api_server}/api/_acme-challenge.${domain}" $ca -d "$token" -H "API-Key: $key"

    done="yes"
fi

if [[ "${1}" = "deploy_cert" ]]; then
    # do nothing for now
    done="yes"
fi

if [[ ! "${done}" = "yes" ]]; then
    echo Unkown hook "${1}"
    exit 1
fi

exit 0
