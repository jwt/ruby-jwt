# JWT
A Ruby implementation of [JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)

## Installing
```bash
gem install jwt
```

## Usage

```ruby
payload = {'some' => 'payload'}
token = JWT.encode(payload, 'secret')
```

Note the resulting JWT will not be encrypted, but verifiable with a secret key.

```ruby
decoded_token = JWT.decode(token, 'secret')
```

If the secret is wrong, it will raise a `JWT::DecodeError` telling you as such. You can still get at the payload by setting the verify argument to false.

```ruby
decoded_token = JWT.decode(token, nil, false) # returns the decoded token, skipped verify process
```

`encode` also allows for different signing algorithms as well as customer headers.

```ruby
token = JWT.encode(payload, secret_key, 'RS256', {'some' => 'header'})
```

## Algorithms

The JWT spec supports several algorithms for cryptographic signing. This library currently supports:

#### HMAC

* HS256	- HMAC using SHA-256 hash algorithm (default)
* HS384	- HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm

#### RSA

* RS256 - RSA using SHA-256 hash algorithm
* RS384 - RSA using SHA-384 hash algorithm
* RS512 - RSA using SHA-512 hash algorithm

Change the algorithm with by setting it in encode:

```ruby
token = JWT.encode({'some' => 'payload'}, 'secret', 'HS512')
```

#### Plaintext

We also support unsigned plaintext JWTs as introduced by draft 03 by explicitly specifying `nil` as the key and algorithm:

```ruby
token = JWT.encode({'some' => 'payload'}, nil, nil)
decoded_token = JWT.decode(token, nil, nil)
```

## Support for reserved claim names
JSON Web Token defines some reserved claim names and defines how they should be used. JWT supports these reserved claim names:

 - `exp` Expiration Time Claim
 - `nbf` Not Before Time Claim
 - `iss` Issuer Claim
 - `aud` Audience Claim
 - `jti` JWT ID Claim
 - `iat` Issued At Claim
 - `sub` Subject Claim

### Expiration Time Claim

You pass the expiration time as a UTC UNIX timestamp (an int). For example:

```ruby
token = JWT.encode({'exp' => 1371720939}, 'secret')
# or
token = JWT.encode({'exp' => Time.now.to_i}, 'secret')
```

Expiration time is automatically verified in `JWT.decode()` and raises `JWT::ExpiredSignature` if the expiration time is in the past:

```ruby
begin
    decoded_token = JWT.decode(token, 'secret')
rescue JWT::ExpiredSignature
    # Signature has expired
end
```

Expiration time will be compared to the current UTC time (as given by Time.now.to_i`), so be sure to use a UTC timestamp or datetime in encoding.

You can turn off expiration time verification with the `verify_expiration` option.

JWT also supports the leeway part of the expiration time definition, which means you can validate a expiration time which is in the past but not very far. For example, if you have a JWT payload with a expiration time set to 30 seconds after creation but you know that sometimes you will process it after 30 seconds, you can set a leeway of 10 seconds in order to have some margin:

```ruby
token = JWT.encode({'exp' => Time.now.to_i + 30}, 'secret')
sleep(32)
# token is now expired
# but with some leeway, it will still validate
JWT.decode(token, 'secret', true, {:leeway => 10})
```

### Not Before Time Claim

You pass the not before time as a UTC UNIX timestamp (an int). For example:
```ruby
token = JWT.encode({'nbf' => 1371720939}, 'secret')
# or
token = JWT.encode({'nbf' => Time.now.to_i}, 'secret')
```

```ruby
begin
    decoded_token = JWT.decode(token, 'secret')
rescue JWT::ImmatureSignature
    # Signature is immature
end
```

Not before time will be compared to the current UTC time (as given by `Time.now.to_i`), so be sure to use a UTC timestamp or datetime in encoding.

You can turn off not before time verification with the `verify_not_before` option.

In a similar way to the expiration time claim, the not before time claim supports the leeway option.

```ruby
token = JWT.encode({'nbf' => Time.now.to_i + 30}, 'secret')
sleep(25)
# token is now immature
# but with some leeway, it will still validate
JWT.decode(token, 'secret', true, {:leeway => 10})
```

# Development and Tests

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
 * Brian Fletcher [@punkle](https://github.com/punkle)
 * Alex [@ZhangHanDong](https://github.com/ZhangHanDong)
 * Tim Rudat [@excpt](https://github.com/excpt) <timrudat@gmail.com> - Maintainer

## License

MIT
