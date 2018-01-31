#
# Dockerfile for an alpine-based python container for python-vipaccess
#
FROM python:2.7-alpine

LABEL maintainer "Prasad Tengse <code@prasadt.com>"

COPY . /usr/src/
WORKDIR /usr/src

RUN apk add --no-cache --virtual .build-deps \
    gcc libc-dev libxml2-dev libxslt-dev
RUN apk add --no-cache libxml2 libxslt jpeg-dev libjpeg
RUN pip install --no-cache-dir lxml oath PyCrypto requests qrcode image \
  && pip install --no-cache-dir . \
  && find /usr/local -name *.pyo -o -name *.pyc -exec rm -f '{}' \; \
  && apk del .build-deps && touch /root/.vipaccess
