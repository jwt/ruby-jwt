# WARNING: This is the 2.x branch of ruby-jwt, currently under heavy development

# JWT

[![Build Status](https://travis-ci.org/excpt/ruby-jwt.svg?branch=refactoring)](https://travis-ci.org/excpt/ruby-jwt)
[![Codeship Status for excpt/moments](https://codeship.com/projects/f94b6890-6dc3-0132-8f82-52110d7a425c/status?branch=master)](https://codeship.com/projects/54274)
[![Code Climate](https://codeclimate.com/github/excpt/ruby-jwt/badges/gpa.svg)](https://codeclimate.com/github/excpt/ruby-jwt)
[![Test Coverage](https://codeclimate.com/github/excpt/ruby-jwt/badges/coverage.svg)](https://codeclimate.com/github/excpt/ruby-jwt)

## Goal

The goal is to implement the complete JWT spec including the underlying specs JWS, JWA, JWK and JWE.

* [JSON Web Token (JWT)](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32)
* [JSON Web Signature (JWS)](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-39)
* [JSON Web Encryption (JWE)](https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-39)
* [JSON Web Key (JWK)](https://tools.ietf.org/html/draft-ietf-jose-json-web-key-39)
* [JSON Web Algorithms (JWA)](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-39)

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

**NONE**

* NONE - No signature

## Installing

```bash
sudo gem install jwt
```

## Usage

Signing a JSON Web Token.

```ruby
JWT.encode({some: 'payload'}, 'secret')
```

Note: The resulting JWT will not be encrypted, but verifiable with a secret key.

```ruby
JWT.decode('someJWTstring', 'secret')
```

If the secret is wrong, it will raise a `JWT::DecodeError` telling you as such. You can still get at the payload by setting the verify argument to false.

```ruby
JWT.decode('someJWTstring', nil, false)
```

Change the algorithm with by setting it in encode:

```ruby
JWT.encode({some: 'payload'}, 'secret', 'HS512')
```

**Plaintext**

We also support unsigned plaintext JWTs as introduced by draft 03 by explicitly specifying `nil` as the key and algorithm:

```ruby
jwt = JWT.encode({some: 'payload'}, nil, nil)
JWT.decode(jwt, nil, nil)
```

## Support for reserved claim names
JSON Web Token defines some reserved claim names and defines how they should be
used. JWT supports these reserved claim names:

 - "exp" (Expiration Time) Claim

### Expiration Time Claim

From [draft 01 of the JWT spec](http://self-issued.info/docs/draft-jones-json-web-token-01.html#ReservedClaimName):

> The exp (expiration time) claim identifies the expiration time on or after
> which the JWT MUST NOT be accepted for processing. The processing of the exp
> claim requires that the current date/time MUST be before the expiration
> date/time listed in the exp claim. Implementers MAY provide for some small
> leeway, usually no more than a few minutes, to account for clock skew. Its
> value MUST be a number containing an IntDate value. Use of this claim is
> OPTIONAL.

You pass the expiration time as a UTC UNIX timestamp (an int). For example:

```ruby
JWT.encode({exp: 1371720939}, 'secret')
JWT.encode({exp: Time.now.to_i()}, 'secret')
```

Expiration time is automatically verified in `JWT.decode()` and raises
`JWT::ExpiredSignature` if the expiration time is in the past:

```ruby
begin
    JWT.decode('JWT_STRING', 'secret')
rescue JWT::ExpiredSignature
    # Signature has expired
end
```

Expiration time will be compared to the current UTC time (as given by
`Time.now.to_i`), so be sure to use a UTC timestamp or datetime in encoding.

You can turn off expiration time verification with the `verify_expiration` option.

JWT also supports the leeway part of the expiration time definition, which
means you can validate a expiration time which is in the past but not very far.
For example, if you have a JWT payload with a expiration time set to 30 seconds
after creation but you know that sometimes you will process it after 30 seconds,
you can set a leeway of 10 seconds in order to have some margin:

```ruby
jwt_payload = JWT.encode({exp: Time.now.to_i + 30}, 'secret')
sleep(32)
# jwt_payload is now expired
# But with some leeway, it will still validate
JWT.decode(jwt_payload, 'secret', true, leeway=10)
```

## Development and Tests

We depend on [Echoe](http://rubygems.org/gems/echoe) for defining gemspec and performing releases to rubygems.org, which can be done with

```bash
rake release
```

The tests are written with rspec. Given you have rake and rspec, you can run tests with

```bash
rake test
```

**If you want a release cut with your PR, please include a version bump according to [Semantic Versioning](http://semver.org/)**

## Contributors

 * Jordan Brough <github.jordanb@xoxy.net>
 * Ilya Zhitomirskiy <ilya@joindiaspora.com>
 * Daniel Grippi <daniel@joindiaspora.com>
 * Jeff Lindsay <progrium@gmail.com>
 * Bob Aman <bob@sporkmonger.com>
 * Micah Gates <github@mgates.com>
 * Rob Wygand <rob@wygand.com>
 * Ariel Salomon (Oscil8)
 * Paul Battley <pbattley@gmail.com>
 * Zane Shannon [@zshannon](https://github.com/zshannon)
 * Tim Rudat <timrudat@gmail.com> [@excpt](https://github.com/excpt)

## License

MIT
