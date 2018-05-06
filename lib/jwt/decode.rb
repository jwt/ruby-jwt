# frozen_string_literal: true

require 'json'

# JWT::Decode module
module JWT
  # Decoding logic for JWT
  class Decode
    def self.base64url_decode(str)
      str += '=' * (4 - str.length.modulo(4))
      Base64.decode64(str.tr('-_', '+/'))
    end

    def initialize(jwt, verify)
      @jwt = jwt
      @segments = jwt.split('.')
      @verify = verify
      @header = ''
      @payload = ''
      @signature = ''
    end

    def decode_segments
      validate_segment_count
      decode_crypto if @verify
      return_values
    end

    private

    def validate_segment_count
      raise(JWT::DecodeError, 'Not enough or too many segments') unless
        (@verify && segment_length != 3) ||
            (segment_length != 3 || segment_length != 2)
    end

    def segment_length
      @segments.count
    end

    def decode_crypto
      @signature = Decode.base64url_decode(@segments[2])
    end

    def return_values
      [header, payload, @signature, signing_input]
    end

    def header
      parse_and_decode @segments[0]
    end

    def payload
      parse_and_decode @segments[1]
    end

    def signing_input
      @segments.first(2).join('.')
    end

    def parse_and_decode(segment)
      JSON.parse(Decode.base64url_decode(segment))
    rescue JSON::ParserError
      raise JWT::DecodeError, 'Invalid segment encoding'
    end
  end
end
