# frozen_string_literal: true
require 'base64'
require 'jwt/decode'
require 'jwt/default_options'
require 'jwt/encode'
require 'jwt/error'
require 'jwt/signature'
require 'jwt/verify'

# JSON Web Token implementation
#
# Should be up to date with the latest spec:
# https://tools.ietf.org/html/rfc7519
module JWT
  include JWT::DefaultOptions

  module_function

  def decoded_segments(jwt, verify = true)
    raise(JWT::DecodeError, 'Nil JSON web token') unless jwt

    decoder = Decode.new jwt, verify
    decoder.decode_segments
  end

  def encode(payload, key, algorithm = 'HS256', header_fields = {})
    encoder = Encode.new payload, key, algorithm, header_fields
    encoder.segments
  end

  def decode(jwt, key = nil, verify = true, custom_options = {}, &keyfinder)
    raise(JWT::DecodeError, 'Nil JSON web token') unless jwt

    merged_options = DEFAULT_OPTIONS.merge(custom_options)

    decoder = Decode.new jwt, verify
    header, payload, signature, signing_input = decoder.decode_segments
    decode_verify_signature(key, header, payload, signature, signing_input, merged_options, &keyfinder) if verify

    Verify.verify_claims(payload, merged_options)

    raise(JWT::DecodeError, 'Not enough or too many segments') unless header && payload

    [payload, header]
  end

  def decode_verify_signature(key, header, payload, signature, signing_input, options, &keyfinder)
    algo, key = signature_algorithm_and_key(header, payload, key, &keyfinder)

    raise(JWT::IncorrectAlgorithm, 'An algorithm must be specified') unless options[:algorithm]
    raise(JWT::IncorrectAlgorithm, 'Expected a different algorithm') unless algo == options[:algorithm]

    Signature.verify(algo, key, signing_input, signature)
  end

  def signature_algorithm_and_key(header, payload, key, &keyfinder)
    if keyfinder
      key = if keyfinder.arity == 2
              yield(header, payload)
            else
              yield(header)
            end
      raise JWT::DecodeError, 'No verification key available' unless key
    end
    [header['alg'], key]
  end
end
