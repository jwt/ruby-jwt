# frozen_string_literal: true

require 'jwt/signature'
require 'jwt/verify'
require 'jwt/x5c_key_finder'

module JWT
  module DecodeBehaviour
    def segments
      @segments ||= token.split('.')
    end

    def signature
      @signature ||= Base64.urlsafe_decode64(segments[2] || '')
    end

    def header
      @header ||= decode_header(segments[0])
    end

    def payload
      @payload ||= decode_payload(segments[1])
    end

    def signing_input
      segments.first(2).join('.')
    end

    def validate_segment_count!
      segment_count = segments.size

      return if segment_count == 3
      return if segment_count == 2 && (!verify? || header['alg'] == 'none')

      raise JWT::DecodeError, 'Not enough or too many segments'
    end

    def verify_claims!(claim_options)
      Verify.verify_claims(payload, claim_options)
      Verify.verify_required_claims(payload, claim_options)
    end

    def decode_header(raw_header)
      decode_segment_default(raw_header)
    end

    def decode_payload(raw_segment)
      if options[:decode_payload_proc]
        options[:decode_payload_proc].call(raw_segment, header, signature)
      else
        decode_segment_default(raw_segment)
      end
    end

    def decode_segment_default(raw_segment)
      json_parse(Base64.urlsafe_decode64(raw_segment))
    rescue ArgumentError
      raise JWT::DecodeError, 'Invalid segment encoding'
    end

    def json_parse(decoded_segment)
      JWT::JSON.parse(decoded_segment)
    rescue ::JSON::ParserError
      raise JWT::DecodeError, 'Invalid segment encoding'
    end
  end
end
