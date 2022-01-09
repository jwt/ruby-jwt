# frozen_string_literal: true

require 'jwt/signature'
require 'jwt/verify'
require 'jwt/x5c_key_finder'

module JWT
  # Shared methods and behaviours used by ::JWT::DecodeToken and ::JWT::Decode
  module DecodeMethods
    def verify?
      options[:verify] != false
    end

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

    def algorithm_in_header
      header['alg']
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

    def verify_signature_for?(algorithm, key)
      if algorithm.is_a?(String)
        raise JWT::DecodeError, 'No verification key available' unless key

        Array(key).any? { |single_key| Signature.verify(algorithm, single_key, signing_input, signature) }
      else
        algorithm.verify(signing_input, signature, key: key, header: header, payload: payload)
      end
    end

    def resolve_key
      if (jwks = options[:jwks])
        ::JWT::JWK::KeyFinder.new(jwks: jwks).key_for(header['kid'])
      elsif (x5c_options = options[:x5c])
        ::JWT::X5cKeyFinder.new(x5c_options[:root_certificates], x5c_options[:crls]).from(header['x5c'])
      elsif (key = options[:key]).respond_to?(:call)
        key.call(header)
      else
        key
      end
    end

    def verify_claims!(claim_options)
      Verify.verify_claims(payload, claim_options)
      Verify.verify_required_claims(payload, claim_options)
    end

    def decode_header(raw_header)
      decode_segment_default(raw_header)
    end

    def decode_payload(raw_segment)
      if (decode_proc = options[:decode_payload_proc])
        return decode_proc.call(raw_segment, header, signature)
      end

      decode_segment_default(raw_segment)
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
