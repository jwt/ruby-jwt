#!/bin/sh

mkdir -p tmp/certs

openssl genrsa 2048 > tmp/certs/rsa-private.pem
openssl genrsa 2048 > tmp/certs/rsa-wrong-private.pem
openssl rsa -in tmp/certs/rsa-private.pem -pubout > tmp/certs/rsa-public.pem
openssl rsa -in tmp/certs/rsa-wrong-private.pem -pubout > tmp/certs/rsa-wrong-public.pem
openssl ecparam -out tmp/certs/ec256-private.pem -name secp256k1 -genkey
openssl ecparam -out tmp/certs/ec256-wrong-private.pem -name secp256k1 -genkey
openssl ecparam -out tmp/certs/ec384-private.pem -name secp384r1 -genkey
openssl ecparam -out tmp/certs/ec384-wrong-private.pem -name secp384r1 -genkey
openssl ecparam -out tmp/certs/ec512-private.pem -name secp521r1 -genkey
openssl ecparam -out tmp/certs/ec512-wrong-private.pem -name secp521r1 -genkey
openssl ec -in tmp/certs/ec256-private.pem -pubout > tmp/certs/ec256-public.pem
openssl ec -in tmp/certs/ec256-wrong-private.pem -pubout > tmp/certs/ec256-wrong-public.pem
openssl ec -in tmp/certs/ec384-private.pem -pubout > tmp/certs/ec384-public.pem
openssl ec -in tmp/certs/ec384-wrong-private.pem -pubout > tmp/certs/ec384-wrong-public.pem
openssl ec -in tmp/certs/ec512-private.pem -pubout > tmp/certs/ec512-public.pem
openssl ec -in tmp/certs/ec512-wrong-private.pem -pubout > tmp/certs/ec512-wrong-public.pem
