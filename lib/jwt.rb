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

  def encode(payload, key, algorithm = 'HS256', header_fields = {})
    encoder = Encode.new payload, key, algorithm, header_fields
    encoder.segments
  end

  def decode(jwt, key = nil, verify = true, options = {}, &keyfinder)
    raise(JWT::DecodeError, 'Nil JSON web token') unless jwt

    @jwt = jwt
    @key = key
    @verify = verify
    @options = DEFAULT_OPTIONS.merge(options)
    @header,
    @payload,
    @signature,
    @signing_input = Decode.new(jwt, verify).decode_segments
    if verify?
      verify_signature(&keyfinder)
      verify_claims
    end

    raise(JWT::DecodeError, 'Not enough or too many segments') unless @header && @payload

    [@payload, @header]
  end

  private_class_method

  def verify_signature(&keyfinder)
    @key = find_key(&keyfinder) if keyfinder

    raise(JWT::IncorrectAlgorithm, 'An algorithm must be specified') if allowed_algorithms.empty?
    raise(JWT::IncorrectAlgorithm, 'Expected a different algorithm') unless options_includes_algo_in_header?

    Signature.verify(@header['alg'], @key, @signing_input, @signature)
  end

  def find_key(&keyfinder)
    key = (keyfinder.arity == 2 ? yield(@header, @payload) : yield(@header))
    raise JWT::DecodeError, 'No verification key available' unless key
    key
  end

  def allowed_algorithms
    if @options.key?(:algorithm)
      [@options[:algorithm]]
    else
      @options[:algorithms] || []
    end
  end

  def verify?
    @verify
  end

  def verify_claims
    Verify.verify_claims(@payload, @options)
  end

  def options_includes_algo_in_header?
    allowed_algorithms.include? @header['alg']
  end
end
