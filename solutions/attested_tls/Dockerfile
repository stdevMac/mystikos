FROM ubuntu:18.04

RUN apt update && apt install -y build-essential bash libmbedtls-dev libcurl4-openssl-dev

ADD app /app
WORKDIR /app

CMD gcc -g -o /app/client client.c tlscli.c -lmbedtls -lmbedx509 -lmbedcrypto

