# frozen_string_literal: true

require 'base64'
require 'jwt/dsl'
require 'jwt/decode_token'
require 'jwt/json'
require 'jwt/decode'
require 'jwt/default_options'
require 'jwt/encode'
require 'jwt/error'
require 'jwt/jwk'

# JSON Web Token implementation
#
# Should be up to date with the latest spec:
# https://tools.ietf.org/html/rfc7519
module JWT
  include JWT::DefaultOptions

  def self.included(cls)
    cls.include(::JWT::DSL)
  end

  module_function

  def encode(payload, key, algorithm = 'HS256', header_fields = {})
    Encode.new(payload: payload,
               key: key,
               algorithm: algorithm,
               headers: header_fields).segments
  end

  def decode(jwt, key = nil, verify = true, options = {}, &keyfinder)
    Decode.new(jwt, DEFAULT_OPTIONS.merge(key: key, verify: verify).merge(options), &keyfinder).decode_segments
  end
end
