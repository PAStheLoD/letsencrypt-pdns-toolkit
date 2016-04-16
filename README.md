# Let's Encrypt + PowerDNS

# How to deploy?

* it's recommended to run the API server next to pdns, because currently it's quite chatty
* get python3.4+, OpenSSL headers (libssl-dev), pip install the requirements
    * make sure to install libssl-dev before uwsgi install
    * if you already have uwsgi installed try unsintalling it (then deleting the pip wheel cache) and reinstalling it with `pip3 install -v -I uwsgi |& grep https` and make sure you see that the plugins/http/https.c gets compiled
* make a `le-config.json` (see the le-config.sample.json)


* put the client part (cronscript and [letsencrypt.sh](https://github.com/lukas2511/letsencrypt.sh/blob/master/letsencrypt.sh)) on every node/server/host/box/VM where you need the certs renewed (you need openssl, [dig](https://github.com/sequenceiq/docker-alpine-dig/releases), [jq](http://stedolan.github.io/jq/download/) and curl there, but no python) into `/opt/letsencrypt`
* generate new cert(s) (test the cron script(s) and the whole setup), make symlinks out of the old cert files (e.g. you used to have a `/etc/ssl/private/herp.derp.key` and `/etc/ssl/certs/herp.derp.pem`, now make them symlinks that point to `/opt/letsencrypt/certs/herp.derp/privkey.pem` and `/opt/letsencrypt/certs/herp.derp/cert.pem`)
* secure up!
    * run.sh does this for you: on the server `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days XXX -nodes -subj '/CN=much-crypt-such-secure'`

# What if I need the same file in many places?

* Use [Kong](https://github.com/mashape/kong), upload the file ([see](https://getkong.org/plugins/ssl/)) and let Kong take care of that for you
