uwsgi --http 0.0.0.0:8888 --threads 2 -w le-api:app --set-ph config-file=le-config.json
