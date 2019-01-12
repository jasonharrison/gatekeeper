#!/bin/sh
pipenv run gunicorn -c gunicorn_conf.py -k gevent --worker-connections 1000 --preload --certfile=/appdata/ssl/cert.pem --keyfile=/appdata/ssl/privkey.pem -b 0.0.0.0:8443 gatekeeper:app
