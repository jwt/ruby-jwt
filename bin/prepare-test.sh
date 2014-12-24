#!/bin/sh

mkdir -p tmp/certs/jwa

openssl genrsa 2048 > tmp/certs/jwa/rsa-private.pem
openssl genrsa 2048 > tmp/certs/jwa/rsa-wrong-private.pem
openssl rsa -in tmp/certs/jwa/rsa-private.pem -pubout > tmp/certs/jwa/rsa-public.pem
openssl rsa -in tmp/certs/jwa/rsa-wrong-private.pem -pubout > tmp/certs/jwa/rsa-wrong-public.pem
openssl ecparam -out tmp/certs/jwa/ec256-private.pem -name secp256k1 -genkey
openssl ecparam -out tmp/certs/jwa/ec256-wrong-private.pem -name secp256k1 -genkey
openssl ecparam -out tmp/certs/jwa/ec384-private.pem -name secp384r1 -genkey
openssl ecparam -out tmp/certs/jwa/ec384-wrong-private.pem -name secp384r1 -genkey
openssl ecparam -out tmp/certs/jwa/ec512-private.pem -name secp521r1 -genkey
openssl ecparam -out tmp/certs/jwa/ec512-wrong-private.pem -name secp521r1 -genkey
openssl ec -in tmp/certs/jwa/ec256-private.pem -pubout > tmp/certs/jwa/ec256-public.pem
openssl ec -in tmp/certs/jwa/ec256-wrong-private.pem -pubout > tmp/certs/jwa/ec256-wrong-public.pem
openssl ec -in tmp/certs/jwa/ec384-private.pem -pubout > tmp/certs/jwa/ec384-public.pem
openssl ec -in tmp/certs/jwa/ec384-wrong-private.pem -pubout > tmp/certs/jwa/ec384-wrong-public.pem
openssl ec -in tmp/certs/jwa/ec512-private.pem -pubout > tmp/certs/jwa/ec512-public.pem
openssl ec -in tmp/certs/jwa/ec512-wrong-private.pem -pubout > tmp/certs/jwa/ec512-wrong-public.pem
