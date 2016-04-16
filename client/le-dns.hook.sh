#!/bin/bash

# based on @antoifon's script
# https://github.com/antoiner77/letsencrypt.sh-pdns/blob/master/pdns.sh
#

set -e
set -u
set -o pipefail
umask 077



echo "DEBUG: args: $@"

if [[ ! "$#" -gt 3 ]] ; then
    echo "usage: ./$0 [mode] [domain] \"\" [token!]"
    exit 0
fi

domain="${2}"
token="${4}"
timestamp=$(date +%s)

done="no"

if [[ "$1" = "deploy_challenge" ]]; then
  curl "http://$api_server/api/_acme-challenge.$domain" -d "$token"

  while ! dig +trace @8.8.8.8 -t TXT "_acme-challenge.$domain" | grep -- "$token" > /dev/null
    do
       printf "."
       sleep 3
    done
   done="yes"
fi

if [[ "$1" = "clean_challenge" ]]; then
    curl -X DELETE "http://$api_server/api/_acme-challenge.$domain" -d "$token"
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
