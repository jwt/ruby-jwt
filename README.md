# JWT
A Ruby implementation of [JSON Web Token draft 06](http://self-issued.info/docs/draft-jones-json-web-token-06.html).

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

**HMAC**

* HS256	- HMAC using SHA-256 hash algorithm (default)
* HS384	- HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm

**RSA**

* RS256 - RSA using SHA-256 hash algorithm
* RS384 - RSA using SHA-384 hash algorithm
* RS512 - RSA using SHA-512 hash algorithm

Change the algorithm with by setting it in encode:

    JWT.encode({"some" => "payload"}, "secret", "HS512")

**Plaintext**

We also support unsigned plaintext JWTs as introduced by draft 03 by explicitly specifying `nil` as the key and algorithm:

    jwt = JWT.encode({"some" => "payload"}, nil, nil)
    JWT.decode(jwt, nil, nil)

## Development and Tests

We depend on [Echoe](http://rubygems.org/gems/echoe) for defining gemspec and performing releases to rubygems.org, which can be done with

    rake release

The tests are written with rspec. Given you have rake and rspec, you can run tests with

    rake test

## Contributors

 * Jordan Brough <github.jordanb@xoxy.net>
 * Ilya Zhitomirskiy <ilya@joindiaspora.com>
 * Daniel Grippi <daniel@joindiaspora.com>
 * Jeff Lindsay <progrium@gmail.com>
 * Bob Aman <bobaman@google.com>
 * Micah Gates <github@mgates.com>
 * Rob Wygand <rob@wygand.com>
 * Ariel Salomon (Oscil8)
 * Paul Battley <pbattley@gmail.com>

## License

MIT
