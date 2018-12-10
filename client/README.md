Hello!


0. Put the files into `/opt/letsencrypt` 
1. Rename `le.config.sample` to `le.config`
2. Edit it!
3. ```echo | openssl s_client -connect random-secure-string.10.0.0.1.xip.io:8443  2>/dev/null | openssl x509 > api_server_cert.pem```
4. ```ln -s /opt/letsencrypt/letsencrypt-renew /etc/cron.weekly/letsencrypt-renew```

