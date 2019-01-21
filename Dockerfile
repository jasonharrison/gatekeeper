FROM kennethreitz/pipenv:latest
ADD src /appdata
ADD config.ini /appdata
ADD ssl /ssl
EXPOSE 8443
RUN groupadd -g 999 appuser && useradd -r -u 999 -g appuser appuser
RUN chown -hR appuser /appdata /ssl
USER appuser
WORKDIR /appdata
CMD gunicorn -w 4 -c gunicorn_conf.py gatekeeper:app
