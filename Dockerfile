FROM python:3
ADD src /appdata
ADD config.ini /appdata
ADD ssl /appdata/ssl
EXPOSE 8443
RUN apt-get update
RUN pip install pipenv
RUN groupadd -g 999 appuser && useradd -m -r -u 999 -g appuser appuser
RUN chown -hR appuser /appdata 
USER appuser
WORKDIR /appdata
RUN pipenv install
CMD ./run.sh
