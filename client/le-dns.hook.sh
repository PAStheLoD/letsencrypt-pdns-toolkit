#!/bin/bash

# based on @antoifon's script
# https://github.com/antoiner77/letsencrypt.sh-pdns/blob/master/pdns.sh
#

set -e
set -u
set -o pipefail
umask 077


api_server=$(cat le-renew-config.json | jq -r '.api_server')
api_key=$(cat le-renew-config.json | jq -r '.api_key')
api_self_ca=$(cat le-renew-config.json | jq -r '.api_server_cert')

echo "DEBUG: args: $@"

if [[ ! "$#" -gt 3 ]] ; then
    echo "usage: ./$0 [mode] [domain] \"\" [token!]"
    exit 0
fi

domain="${2}"
token="${4}"
timestamp=$(date +%s)


if [[ $api_self_ca != "null" ]] ; then
    if [[ $(openssl s_client -connect $api_server -CAfile $api_self_ca |& grep 'Verify' | grep '0 (ok)' | wc -l) != 1 ]] ; then
        echo "Cannot verify remote cert"
        exit 1
    fi
    curl="curl --cacert $api_self_ca -k \"https://$api_server/api/_acme-challenge.$domain\""
else
    curl="curl \"http://$api_server/api/_acme-challenge.$domain\""
fi


done="no"

if [[ "$1" = "deploy_challenge" ]]; then
  $curl -d "$token" -H "API-Key: \"$api_key\""

  while ! dig +trace @8.8.8.8 -t TXT "_acme-challenge.$domain" | grep -- "$token" > /dev/null
    do
       printf "."
       sleep 3
    done
   done="yes"
fi

if [[ "$1" = "clean_challenge" ]]; then
    $curl -X DELETE -d "$token" -H "API-Key: \"$api_key\""
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
