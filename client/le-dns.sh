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
    echo "ERROR: Missing le.config" >&2
    exit 1
fi

api_server="$(grep -Po '^(?!(\s*#+)+)\s*api_server="?\Khttps://[a-z0-9.-]+(:[0-9]+)?(?="?$)' le.config || true)"

if [[ $api_server = "" ]] ; then
    echo "ERROR: API Server not configured (missing api_server=\"https://...\" from le.config)" >&2
    exit 1
fi

api_server_cert="$(grep -Po '^(?!(\s*#+)+)\s*api_server_cert="?\K[^"]+(?="?$)' le.config || true)"


which dig &>/dev/null || { echo "ERROR: dig program seems to be missing" >&2 ; exit 1 ; }


function test_server() {
    local url="${1}"
    local cert_hack="${2}"

    # shellcheck disable=SC2086
    curl_test_output="$(curl -sv "${url}" $cert_hack -I 2>&1)"

    if [[ $(echo "$curl_test_output" | grep -c 'SSL certificate verify ok') = 0 ]] ; then
        echo "ERROR: API server TLS verification failed :(" >&2
        openssl s_client -connect "$server_host:$port" |& grep 'Verify return code:'
        exit 1
    fi

    if [[ $(echo "$curl_test_output" | grep -Poc  '^< HTTP/1\.1' || true) = 0 ]] ; then
        echo "ERROR: API server cannot be reached" >&2
        exit 1
    fi
}
function parse_conf() {
    [[ $(grep -Po "domain=\"$domain\"" le.config | wc -l) != 1 ]] && {
        echo "ERROR: domain=\"$domain\" must be configured in le.config" >&2
        exit 1
    }

    key=$(grep -P "^(?!(\s*#+)+)\s*domain=\"?$domain\"?" le.config | grep -Po "key=\"?\K[^\"]+(?=\"?(\s+|\$))" || :)

    [[ "$key" = "" ]] && {
        echo "ERROR: Missing key=\"...\" from config for domain: $domain" >&2
        exit 1
    }
    echo "DEBUG: conf parsed" >&2
}

function parse_args() {
    [[ ! "$#" -gt 3 ]] && {
        echo "INFO: usage: ./$0 [mode] [domain] \"\" [token!]" >&2
        exit 0
    }

    domain="${2}"
    token="${4}"

    parse_conf
}

function clean_domain() {
    parse_conf
    o=$(curl -s -X DELETE "${api_server_url}_acme-challenge.${domain}" $ca -H "API-Key: $key" 2>&1) || {
        echo "ERROR: error during cleaning: $o" >&2
    }

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
            ca="--resolve le-crypt:$port:$(dig +short "$server_host" | tail -n 1) --cacert $api_server_cert"
        fi
        api_server_url="https://le-crypt:$port/api/"

        test_server "$api_server_url" "$ca"

    } || {
        echo "ERROR: api_server_cert is set but not readable" >&2
        exit 1
    }
} || {
    # try the server, maybe it has a valid cert
    api_server_url="${api_server}/api/"

    test_server "$api_server_url"

    ca=""
}

echo "DEBUG: args: $*" >&2
[[ "$1" = "startup_hook" ]] || [[ "${1}" = "exit_hook" ]] || [[ "${1}" = "unchanged_cert" ]] || [[ "${1}" = "deploy_cert" ]] && {
    # do nothing for now
    echo "DEBUG: noop $1" >&2
    exit 0
}

[[ "$1" = 'this_hookscript_is_broken__dehydrated_is_working_fine__please_ignore_unknown_hooks_in_your_script' ]] && exit 0
[[ "$1" = 'sync_cert' ]] && exit 0

done="no"

[[ "$1" = "deploy_challenge" ]] && {
  parse_args "$@"
  curl_output=$(curl -s "${api_server_url}_acme-challenge.${domain}" $ca -d "$token" -H "API-Key: $key")
  echo "$curl_output" | grep -q "^ok$" || {
      echo "$curl_output" | grep -qi "unauthorized" && {
          echo "ERROR: wrong key for domain" >&2
          exit 1
      }

      echo "ERROR: failed to deploy challenge :/" >&2
      echo "$curl_output" >&2
      exit 1
  }

  t=30
  while ! dig +trace @8.8.8.8 -t TXT "_acme-challenge.${domain}" | grep -- "$token" > /dev/null ; do
       printf "."
       sleep 3
       (( t-- ))
       [[ "$t" -lt 1 ]] && { break; }
  done

  echo "DEBUG: $1 done" >&2
  exit 0
}

[[ "${1}" = "generate_csr" ]] && {
    # args: generate_csr *.endticket.com /opt/letsencrypt-pdns-toolkit/client/certs/endticket.com *.endticket.com endticket.com
    echo "DEBUG: parsing domain from $2" >&2
    domain=$(echo "$2" | grep -Po '^(\*\.)?\K.*') || { echo "ERROR: failed to parse domain from $2" >&2 ; exit 1; }

    echo "DEBUG: domain = $domain" >&2

    clean_domain

    echo "DEBUG: cleaned domain $domain" >&2

    exit 0
}


[[ "$1" = "clean_challenge" ]] || [[ "${1}" = "invalid_challenge" ]] || [[ "${1}" = "request_failure" ]] && {
    [[ ! "$#" -gt 2 ]] && { echo "ERROR: missing arg domain!" ;  exit 1;  }

    domain="${2}"

    clean_domain

    echo "DEBUG: done $1" >&2

    done="yes"
}

[[ ! "${done}" = "yes" ]] && {
    echo "DEBUG: Ignoring unkown hook ${1}" >&2
    exit 0
} || {
    # we're done
    exit 0
}

[[ ! "$#" -gt 0 ]] && {
    echo "INFO: usage: ./$0 [mode]"
    echo "INFO: usage: ./$0 [mode] [domain] \"\" [token!]"
    exit 0
}

exit 0
