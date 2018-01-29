#
# Dockerfile for an alpine-based python container for python-vipaccess
#
FROM python:2.7-alpine

LABEL maintainer "Prasad Tengse <code@prasadt.com>"

COPY . /usr/src/
WORKDIR /usr/src

RUN apk add --no-cache --virtual .build-deps \
    gcc libc-dev libxml2-dev libxslt-dev \
  && apk add --no-cache libxml2 libxslt \
  && pip install --no-cache-dir lxml oath pycryptodome requests image qrcode\
  && pip install --no-cache-dir . \
  && find /usr/local -name *.pyo -o -name *.pyc -exec rm -f '{}' \; \
  && apk del .build-deps && touch /root/.vipaccess

ENTRYPOINT ["/usr/local/bin/vipaccess"]
