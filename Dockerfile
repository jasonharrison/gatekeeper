FROM kennethreitz/pipenv:latest
ADD src /appdata
ADD config.ini /appdata
ADD ssl /appdata/ssl
EXPOSE 8443
RUN groupadd -g 999 appuser && useradd -m -r -u 999 -g appuser appuser
RUN mkdir /venv
RUN chown -hR appuser /appdata  && chown -hR appuser /venv
USER appuser
WORKDIR /appdata
CMD python3 web_tornado.py
