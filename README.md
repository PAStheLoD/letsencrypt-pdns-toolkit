# Let's Encrypt + PowerDNS

# How to deploy?

* it's recommended to run the API server next to pdns, because currently it's quite chatty
* get python3.4+, pip install the requirements
* make a `le-config.json` (see the le-config.sample.json)


* put the client part (cronscript and letsencrypt.sh) on every node/server/host/box/VM where you need the certs renewed (you need openssl and curl there, but no python) into `/opt/letsencrypt`
* generate new cert(s) (test the cron script(s) and the whole setup), make symlinks out of the old cert files (e.g. you used to have a `/etc/ssl/private/herp.derp.key` and `/etc/ssl/certs/herp.derp.pem`, now make them symlinks that point to `/opt/letsencrypt/certs/herp.derp/privkey.pem` and `/opt/letsencrypt/certs/herp.derp/cert.pem`)

# What if I need the same file in many places?

* Use [Kong](https://github.com/mashape/kong), upload the file ([see](https://getkong.org/plugins/ssl/)) and let Kong take care of that for you
