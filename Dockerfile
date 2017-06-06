#
# Dockerfile for an alpine-based python container for python-vipaccess
#
FROM python:2.7-alpine

LABEL maintainer "Kayvan Sylvan <kayvansylvan@gmail.com>"

RUN apk add --no-cache libxml2-dev libxslt-dev gcc libc-dev
RUN pip install lxml oath PyCrypto requests

COPY . /usr/src/
WORKDIR /usr/src
RUN pip install .
ENTRYPOINT ["/usr/local/bin/vipaccess"]
