#!/bin/bash

# based on @antoifon's script
# https://github.com/antoiner77/letsencrypt.sh-pdns/blob/master/pdns.sh
#

# set -x
set -e
set -u
set -o pipefail
umask 077



if [[ ! -r le.config ]] ; then
    echo "Missing le.config"
    exit 1
fi

api_server="$(grep -Po '^(?!(\s*#+)+)\s*api_server="?\Khttps://[a-z0-9.-]+(:[0-9]+)?(?="?$)' le.config || true)"

if [[ $api_server = "" ]] ; then
    echo "API Server not configured (missing api_server=\"https://...\" from le.config)"
    exit 1
fi

api_server_cert="$(grep -Po '^(?!(\s*#+)+)\s*api_server_cert="?\K[^"]+(?="?$)' le.config || true)"

function test_server() {
    local url="${1}"
    local cert_hack="${2}"

    # shellcheck disable=SC2086
    curl_test_output="$(curl -sv "${url}" $cert_hack -I 2>&1)"

    if [[ $(echo "$curl_test_output" | grep -c 'server certificate verification failed') != 0 ]] ; then
        echo "ERROR: API server TLS verification failed :("
        openssl s_client -connect "$server_host:$port" |& grep 'Verify return code:'
        exit 1
    fi

    if [[ $(echo "$curl_test_output" | grep -Poc  '^< HTTP/1\.1' || true) = 0 ]] ; then
        echo "ERROR: API server cannot be reached"
        exit 1
    fi
}

[[ "$api_server_cert" != "" ]] && {
    [[ -r "$api_server_cert" ]] && {
        if [[ $(echo "$api_server" | grep -Pc ':[0-9]+$') = 1 ]] ; then
            port=$(echo "$api_server" | grep -Po ':\K[0-9]+$')
        else
            port=443
        fi

        server_host=$(echo "$api_server" | grep -Po 'https://\K[a-z0-9.-]+' | head -n1)

        if [[ $(echo "$server_host" | grep -P '^([0-9]+\.)+[0-9]+$') = "$server_host" ]] ; then
            ca="--resolve le-crypt:$port:$server_host --cacert $api_server_cert"
        else
            ca="--resolve le-crypt:$port:$(dig +short "$server_host") --cacert $api_server_cert"
        fi
        api_server_url="https://le-crypt:$port/api/"

        test_server "$api_server_url" "$ca"

    } || {
        echo "api_server_cert is set but not readable"
        exit 1
    }
} || {
    # try the server, maybe it has a valid cert
    api_server_url="${api_server}/api/"

    test_server "$api_server_url"

    ca=""
}

echo "DEBUG: args: $*"

[[ ! "$#" -gt 0 ]] && {
    echo "usage: ./$0 [mode]"
    echo "usage: ./$0 [mode] [domain] \"\" [token!]"
    exit 0
}

[[ "$1" = "startup_hook" ]] || [[ "${1}" = "exit_hook" ]] || [[ "${1}" = "unchanged_cert" ]] || [[ "${1}" = "deploy_cert" ]] || [[ "${1} = "generate_csr" ]] && {
    # do nothing for now
    exit 0
}

[[ ! "$#" -gt 3 ]] && {
    echo "usage: ./$0 [mode] [domain] \"\" [token!]"
    exit 0
}

domain="${2}"
token="${4}"

[[ $(grep -Po "domain=\"$domain\"" le.config | wc -l) != 1 ]] && {
    echo "domain=\"$domain\" must be configured in le.config"
    exit 1
}

key="$(grep -Po "^(?!(\s*#+)+)\s*domain=\"?$domain\"?\s+key=\"?\K[^\"]+(?=\"?(\s+|\$))" le.config || true)"

[[ "$key" = "" ]] && {
    echo "Missing key=\"...\" from config for domain: $domain"
    exit 1
}

done="no"

[[ "$1" = "deploy_challenge" ]] && {
  curl_output=$(curl -s "${api_server_url}_acme-challenge.${domain}" $ca -d "$token" -H "API-Key: $key")
  echo "$curl_output" | grep -q "^ok$" || {
      echo "$curl_output" | grep -qi "unauthorized" && {
          echo "wrong key for domain"
          exit 1
      }

      echo "ERROR: failed to deploy challenge :/"
      echo "$curl_output"
      exit 1
  }

  while ! dig +trace @8.8.8.8 -t TXT "_acme-challenge.${domain}" | grep -- "$token" > /dev/null ; do
       printf "."
       sleep 3
  done

  done="yes"
}

[[ "$1" = "clean_challenge" ]] || [[ "${1}" = "invalid_challenge" ]] || [[ "${1}" = "request_failure" ]] && {
    curl -s -X DELETE "${api_server_url}_acme-challenge.${domain}" $ca -d "$token" -H "API-Key: $key"

    done="yes"
}



[[ ! "${done}" = "yes" ]] && {
    echo Unkown hook "${1}"
    exit 1
}

exit 0
