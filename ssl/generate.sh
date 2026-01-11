#!/bin/sh
openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -config openssl.cnf -keyout server.key -out server.crt
