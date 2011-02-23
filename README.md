# JWT
A Ruby implementation of [JSON Web Token draft 01](http://self-issued.info/docs/draft-jones-json-web-token-01.html).

## Installing

    sudo gem install jwt

## Usage

    JWT.encode({"some" => "payload"}, "secret")

Note the resulting JWT will not be encrypted, but verifiable with a secret key.

    JWT.decode("someJWTstring", "secret")

If the secret is wrong, it will raise a `JWT::DecodeError` telling you as such. You can still get at the payload by setting the verify argument to false.

    JWT.decode("someJWTstring", nil, false)

## Algorithms

The JWT spec supports several algorithms for cryptographic signing. This library currently supports:

* HS256	- HMAC using SHA-256 hash algorithm (default)
* HS384	- HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm

Change the algorithm with by setting it in encode:

    JWT.encode({"some" => "payload"}, "secret", "HS512")

## Tests

The tests are written with rspec. Given you have rake and rspec, you can run tests with

    rake test

## License

MIT