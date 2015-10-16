#!/bin/sh
#From NIST
#The recommended key length for data which should be available > 2016
#is 2048 (RSA)

openssl genrsa -out ../build/ca.key  4096
openssl req -new -x509 -nodes -sha1 -days 3650 -key ../build/ca.key -out ../build/ca.crt -config ca.conf
openssl x509 -trustout -inform PEM -in ../build/ca.crt -outform DER -out ../build/ca.pfx
