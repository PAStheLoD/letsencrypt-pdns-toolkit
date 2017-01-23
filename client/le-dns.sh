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


if [[ $(grep -Po '^(?!(\s*#+)+)\s*api_server=\K.*$' le.config) = "" ]] ; then
    echo "API Server not configured (missing api_server=\"...\" from le.config)"
    exit 1
fi

api_server=$(grep -Po '^(?!(\s*#+)+)\s*api_server="?\K[^"]+(?="?$)' le.config)


api_server_cert="$(grep -Po '^(?!(\s*#+)+)\s*api_server_cert="?\K[^"]+(?="?$)' le.config)"

if [[ "$api_server_cert" != "" ]] ; then
    if [[ -r "$api_server_cert" ]] ; then
        if [[ $(echo "$api_server" | grep -Pc ':[0-9]+$') = 1 ]] ; then
            port=$(echo "$api_server" | grep -Po ':\K[0-9]+$')
        else
            port=8443
        fi

        server_host=$(echo "$api_server" | grep -Po '[^:]+' | head -n1)

        if [[ $(echo "$server_host" | grep -P '^([0-9]+\.)+[0-9]+$') = "$server_host" ]] ; then
            ca="--resolve le-crypt:$port:$server_host --cacert $api_server_cert"
        else
            ca="--resolve le-crypt:$port:$(dig +short "$server_host") --cacert $api_server_cert"
        fi
        scheme="https"
        api_server="le-crypt:$port"
        
        # shellcheck disable=SC2086 
        curl_test_output="$(curl -sv "${scheme}://${api_server}/api/" $ca -I 2>&1)"

        if [[ $(echo "$curl_test_output" | grep -c 'server certificate verification failed') != 0 ]] ; then
            echo "ERROR: API server TLS verification failed :("
            openssl s_client -connect "$server_host:$port" |& grep 'Verify return code:'
            exit 1
        fi

        if [[ $(echo "$curl_test_output" | grep -Poc  '^< HTTP/1\.1') = 0 ]] ; then
            echo "ERROR: API server cannot be reached"
            exit 1
        fi
    else
        echo "api_server_cert is set but not readable"
        exit 1
    fi
else
    scheme="http"
    ca=""
fi

echo "DEBUG: args: $*"

if [[ ! "$#" -gt 3 ]] ; then
    echo "usage: ./$0 [mode] [domain] \"\" [token!]"
    exit 0
fi

domain="${2}"
token="${4}"

if [[ $(grep -Po "domain=\"$domain\"" le.config | wc -l) != 1 ]] ; then
    echo "domain=\"$domain\" must be configured in le.config"
    exit 1
fi

key="$(grep -Po "^(?!(\s*#+)+)\s*domain=\"?$domain\"?\s+key=\"?\K[^\"]+(?=\"?(\s+|\$))" le.config)"

done="no"

if [[ "$1" = "deploy_challenge" ]]; then
  curl_output=$(curl -s "${scheme}://${api_server}/api/_acme-challenge.${domain}" $ca -d "$token" -H "API-Key: $key")
  if [[ $(echo "$curl_output" | grep -c "^ok$") = 0 ]] ; then
      echo "ERROR: failed to deploy challenge :/"
      exit 1
  fi

  while ! dig +trace @8.8.8.8 -t TXT "_acme-challenge.${domain}" | grep -- "$token" > /dev/null
    do
       printf "."
       sleep 3
    done
   done="yes"
fi

if [[ "$1" = "clean_challenge" ]]; then
    curl -s -X DELETE "${scheme}://${api_server}/api/_acme-challenge.${domain}" $ca -d "$token" -H "API-Key: $key"

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
