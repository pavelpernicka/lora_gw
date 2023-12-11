#!/bin/sh
# generate private
openssl genpkey -algorithm RSA -out files/certs/rsa_private.pem -pkeyopt rsa_keygen_bits:2048
# generate public from private
openssl rsa -in files/certs/rsa_private.pem -pubout -out files/certs/rsa_public.pem
