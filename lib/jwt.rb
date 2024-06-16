# frozen_string_literal: true

require 'jwt/version'
require 'jwt/base64'
require 'jwt/json'
require 'jwt/decode'
require 'jwt/configuration'
require 'jwt/deprecations'
require 'jwt/encode'
require 'jwt/error'
require 'jwt/jwk'

# JSON Web Token implementation
#
# Should be up to date with the latest spec:
# https://tools.ietf.org/html/rfc7519
module JWT
  extend ::JWT::Configuration

  module_function

  def encode(payload, key, algorithm = 'HS256', header_fields = {})
    Encode.new(payload: payload,
               key: key,
               algorithm: algorithm,
               headers: header_fields).segments
  end

  def decode(jwt, key = nil, verify = true, options = {}, &keyfinder) # rubocop:disable Style/OptionalBooleanParameter
    if (res = Decode.new(jwt, key, verify, configuration.decode.to_h.merge(options), &keyfinder).decode_segments)
      begin
        jwt.split('.').each { |part| ::Base64.urlsafe_decode64(part) }
      rescue ArgumentError
        issue_warning = true
      end

      if issue_warning
        warn('[DEPRECATION WARNING] Invalid base64 input detected, could be because of invalid padding, trailing whitespaces or newline chars. Graceful handling of invalid input will be dropped in the next major version of ruby-jwt', uplevel: 1)
      end
    end

    res
  end
end
