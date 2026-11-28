# Upgrading ruby-jwt to >= 3.3.2

## Claim checks fail when the claim is missing

The `iss` and `sub` checks no longer pass for a token that lacks the claim, and the `iss`, `aud`, `sub` and `jti` checks treat a payload that is not a Hash as having no claims. Each check raises its own error, such as `JWT::InvalidIssuerError`, instead of passing or raising a plain Ruby error.

- **`iss`:** a token without `iss` fails, whatever the expected issuers are. Issuer Procs and Methods are no longer called with `nil`, so a Proc written to accept a missing issuer now rejects the token. `nil` among the expected issuers, as in `iss: [ENV['JWT_ISSUER']]` with the variable unset, no longer matches a token without `iss`. Regexp, Proc and Method matchers are only used for a String `iss`; any other value has to equal one of the expected issuers.
- **`aud`:** `nil` among the expected audiences no longer matches a token whose `aud` is `[null]`.
- **`sub`:** a token without `sub` fails, and so does every token when the expected subject is blank. This includes `:sub` given to `JWT::EncodedToken#verify_claims!` or `JWT::Claims.verify_payload!` without a value, which used to pass for tokens without `sub`.
- **Payloads that are not a Hash:** Hash-like objects, such as `ActionController::Parameters`, given to `JWT::Claims.verify_payload!` or used as a `JWT::Token` payload now fail these checks. Convert them with `to_h` first. `JWT.decode` is not affected, because it parses the payload from JSON.

## Public keys and certificates are rejected as HMAC secrets

`HS256`, `HS384` and `HS512` reject the PEM and SSH encodings listed below when used as the shared secret. Public keys in other encodings, including DER, bare base64 and JWK JSON strings, are not detected and can still act as HMAC secrets; do not include them in mixed asymmetric/HMAC key lists. Signing with a rejected encoding raises `JWT::EncodeError`, and verifying with one raises `JWT::VerificationKeyError`, both with the message `HMAC key cannot be a public key or certificate`. This covers:

- a public key in PEM, such as `-----BEGIN PUBLIC KEY-----` or `-----BEGIN RSA PUBLIC KEY-----`;
- a certificate in PEM, such as `-----BEGIN CERTIFICATE-----`;
- an OpenSSH public key or certificate, such as `ssh-ed25519 AAAA…`, including a line from `authorized_keys`;
- an RFC 4716 SSH public key (`---- BEGIN SSH2 PUBLIC KEY ----`).

A public key is known to others by design, so anyone holding it could sign tokens that verify with such a secret. If you use one, replace it with a randomly generated secret. Tokens signed with the old secret will no longer verify. A private key used as the secret is not affected, unless the same string also holds a public key or certificate, as a combined key and certificate file does.

## Every key is tried when several are given

When several keys are given for verification, a key that cannot be used for the algorithm, such as an EC key for `HS256` or an EC key on another curve, no longer stops the remaining keys from being tried. A token now verifies if any key matches. When none does, the error for the first unusable key is raised, as before.

If you allow an HMAC algorithm alongside an asymmetric one, every String in the key list can now act as an HMAC secret, wherever it is in the list. RSA, ECDSA and EdDSA only accept key objects, so a public key given as a String, in any format, does nothing for them and should not be in the list. Keep the keys for each algorithm apart instead, for example with a key finder block that returns keys based on the token's `alg` header.

# Upgrading ruby-jwt to >= 3.3.0

## Error hierarchy revamp

The [error classes were reorganised](https://github.com/jwt/ruby-jwt/pull/722) under a new `JWT::Error` base class, so failures can be rescued by category instead of one class at a time:

- `JWT::Error` is the base class for everything the gem raises.
- `JWT::TokenError` covers every failure in processing a token, and splits into `JWT::MalformedTokenError` (the token is structurally invalid), `JWT::SignatureError` (signature and algorithm problems) and `JWT::ClaimValidationError` (a claim did not verify).
- `JWT::VerificationKeyError`, a subclass of `JWT::VerificationError`, says the key or algorithm given for verification cannot be used, as opposed to a signature that does not match.

### Backwards compatibility

This is a backwards compatible change for effectively every application. The new classes were inserted above the existing ones rather than replacing them, so every error class you already rescue keeps its name, its meaning and everything it used to catch. In the ordinary case, upgrading needs no code change at all.

There is one exception, and it is narrow enough to be worth stating precisely. It applies only if all three of the following are true:

1. You rescue around `JWT.encode`, not around `JWT.decode`.
2. The class you rescue is `JWT::DecodeError`, `JWT::IncorrectAlgorithm`, `JWT::UnsupportedEcdsaCurve` or `ArgumentError`.
3. That rescue is reached at all, which takes a key or algorithm that cannot sign in the first place.

If any one of the three does not hold, there is nothing to do. If all three do, the fix is a one line change, described in the next section.

Why that is a small target in practice:

- **Decoding is untouched.** `JWT::DecodeError` is deprecated in favour of the classes above, but it keeps its meaning: every error class except `JWT::EncodeError` still inherits from it. A `rescue JWT::DecodeError` around `JWT.decode` catches everything it caught before, and the specific classes it has always raised, such as `JWT::ExpiredSignature`, are unchanged.
- **Signing that currently works is untouched.** Every case in the table below is an unusable key or algorithm, a misconfiguration that fails on every call made with that key. None of them can be triggered by a particular payload or token, so an application that signs tokens successfully today does not reach them at all.
- **Failures you let escape are untouched.** All of these raised before and still raise; only the class changed. Code that does not rescue them behaves exactly as it did.

One decode-side behaviour did change, but in the direction of catching more: `RS*` and `PS*` now reject a key of the wrong type with a `JWT::VerificationKeyError`, which is a `JWT::DecodeError`, instead of letting a `NoMethodError` escape.

### Signing failures now raise `JWT::EncodeError`

Signing failures used to surface as decode errors, and are now consistently `JWT::EncodeError`, which is deliberately not a `JWT::DecodeError`:

| Signing with | Used to raise | Now raises |
| --- | --- | --- |
| a `nil`, empty or too short HMAC key | `JWT::DecodeError` | `JWT::EncodeError` |
| an ECDSA key whose curve does not match the algorithm | `JWT::IncorrectAlgorithm` | `JWT::EncodeError` |
| an ECDSA key on an unsupported curve | `JWT::UnsupportedEcdsaCurve` | `JWT::EncodeError` |
| a JWK whose `alg` does not match the algorithm | `JWT::DecodeError` | `JWT::EncodeError` |
| an `RS*` or `PS*` public key | `ArgumentError` | `JWT::EncodeError` |

If you wrap `JWT.encode` in `rescue JWT::DecodeError`, `rescue JWT::IncorrectAlgorithm` or `rescue JWT::UnsupportedEcdsaCurve`, rescue `JWT::EncodeError` or `JWT::Error` instead.

### Why this is a minor release

The exception described above is a real incompatibility, and 3.3.0 is still deliberately a minor release rather than a new major.

The reason is that nothing here turns a call that used to succeed into one that fails, or the other way round. Every case in the table raised an error before and raises an error now, only under a different class. No token is signed that would previously have been refused, no token verifies that would previously have been rejected, and no signature is produced or accepted on different terms than before. What changed is which `rescue` clause matches on a path that was already failing.

Weighed against the cost of a second major migration so soon after 3.0.0, that did not seem to warrant one.

If you find a case where this change affects whether a call succeeds, rather than which error it raises when it fails, please [open an issue](https://github.com/jwt/ruby-jwt/issues). That would be a bug rather than an intended consequence of the reorganisation.

# Upgrading ruby-jwt to >= 3.0.0

## Removal of the indirect [RbNaCl](https://github.com/RubyCrypto/rbnacl) dependency

Historically, the set of supported algorithms was extended by including the `rbnacl` gem in the application's Gemfile. On load, ruby-jwt tried to load the gem and, if available, extend the algorithms to those provided by the `rbnacl/libsodium` libraries. This indirect dependency has caused some maintenance pain and confusion about which versions of the gem are supported.

Some work to ease the way alternative algorithms can be implemented has been done. This enables the extraction of the algorithm provided by `rbnacl`.

The extracted algorithms now live in the [jwt-eddsa](https://rubygems.org/gems/jwt-eddsa) gem.

### Dropped support for HS512256

The algorithm HS512256 (HMAC-SHA-512 truncated to 256-bits) is not part of any JWA/JWT RFC and therefore will not be supported anymore. It was part of the HMAC algorithms provided by the indirect [RbNaCl](https://github.com/RubyCrypto/rbnacl) dependency. Currently, there are no direct substitutes for the algorithm.

### `JWT::EncodedToken#payload` will raise before token is verified

To avoid accidental use of unverified tokens, the `JWT::EncodedToken#payload` method will raise an error if accessed before the token signature has been verified.

To access the payload before verification, use the method `JWT::EncodedToken#unverified_payload`.

## Stricter requirements on Base64 encoded data

Base64 decoding will no longer fallback on the looser RFC 2045. The biggest difference is that the looser version was ignoring whitespaces and newlines, whereas the stricter version raises errors in such cases.

If you, for example, read tokens from files, there could be problems with trailing newlines. Make sure you trim your input before passing it to the decoding mechanisms.

## Claim verification revamp

Claim verification has been [split into separate classes](https://github.com/jwt/ruby-jwt/pull/605) and has [a new API](https://github.com/jwt/ruby-jwt/pull/626), leading to the following deprecations:

- The `::JWT::ClaimsValidator` class will be removed in favor of the functionality provided by `::JWT::Claims`.
- The `::JWT::Claims::verify!` method will be removed in favor of `::JWT::Claims::verify_payload!`.
- The `::JWT::JWA.create` method will be removed.
- The `::JWT::Verify` class will be removed in favor of the functionality provided by `::JWT::Claims`.
- Calling `::JWT::Claims::Numeric.new` with a payload will be removed in favor of `::JWT::Claims::verify_payload!(payload, :numeric)`.
- Calling `::JWT::Claims::Numeric.verify!` with a payload will be removed in favor of `::JWT::Claims::verify_payload!(payload, :numeric)`.

## Algorithm restructuring

The internal algorithms were [restructured](https://github.com/jwt/ruby-jwt/pull/607) to support extensions from separate libraries. The changes led to a few deprecations and new requirements:

- The `sign` and `verify` static methods on all the algorithms (`::JWT::JWA`) will be removed.
- Custom algorithms are expected to include the `JWT::JWA::SigningAlgorithm` module.

## Base64 the `k´ value for HMAC JWKs

The gem was missing the Base64 encoding and decoding when representing and parsing a HMAC key as a JWK. This issue is now addressed. The added encoding will break compatibility with JWKs produced by older versions of the gem.
