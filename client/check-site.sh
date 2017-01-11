#!/bin/bash

[[ "$1" = "" ]] && exit 1

D=$(echo "$1" | sed 's/[[:upper:]]*/\L&/')

[[ $(echo "$1" | grep -Pc '^[a-z0-9.-]+(:[0-9]+)?$') = 0 ]] && { echo "not a domain" ; exit 2 ; }

P=$(echo "$1" | grep -P '^[a-z0-9.-]+:\K[0-9]+$')
if [[ "$P" = "" ]] ; then 
  P=443
fi

echo | openssl s_client -connect "$1:$P" 2>/dev/null | openssl x509  -noout -text  | grep After
