#!/bin/sh

rm -rf tmp/certs/*.pem

mkdir -p tmp/certs

# RSA KEYS
openssl genrsa 1024 > tmp/certs/rsa-1024-private.pem
openssl rsa -in tmp/certs/rsa-1024-private.pem -pubout > tmp/certs/rsa-1024-public.pem
openssl genrsa 2048 > tmp/certs/rsa-2048-private.pem
openssl genrsa 2048 > tmp/certs/rsa-2048-wrong-private.pem
openssl rsa -in tmp/certs/rsa-2048-private.pem -pubout > tmp/certs/rsa-2048-public.pem
openssl rsa -in tmp/certs/rsa-2048-wrong-private.pem -pubout > tmp/certs/rsa-2048-wrong-public.pem
openssl genrsa 4096 > tmp/certs/rsa-4096-private.pem
openssl rsa -in tmp/certs/rsa-4096-private.pem -pubout > tmp/certs/rsa-4096-public.pem

# ECDSA KEYS
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
