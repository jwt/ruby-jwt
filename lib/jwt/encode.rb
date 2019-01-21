# frozen_string_literal: true

# JWT::Encode module
module JWT
  # Encoding logic for JWT
  class Encode
    ALG_NONE = 'none'.freeze
    ALG_KEY  = 'alg'.freeze
    EXP_KEY  = 'exp'.freeze
    EXP_KEYS = [EXP_KEY, EXP_KEY.to_sym].freeze

    def initialize(options)
      @payload   = options[:payload]
      @key       = options[:key]
      @algorithm = options[:algorithm]
      @headers   = options[:headers]
    end

    def segments
      @segments ||= combine(encoded_header_and_payload, encoded_signature)
    end

    private

    def validate_payload!
      return unless @payload && @payload.is_a?(Hash)

      validate_exp!
    end

    def validate_exp!
      return if EXP_KEYS.all? { |key| !@payload.key?(key) || @payload[key].is_a?(Integer) }

      raise InvalidPayload, 'exp claim must be an integer'
    end

    def encoded_header
      @encoded_header ||= encode_header
    end

    def encoded_payload
      @encoded_payload ||= encode_payload
    end

    def encoded_signature
      @encoded_signature ||= encode_signature
    end

    def encoded_header_and_payload
      @encoded_header_and_payload ||= combine(encoded_header, encoded_payload)
    end

    def encode_header
      encode(@headers.merge(ALG_KEY => @algorithm))
    end

    def encode_payload
      validate_payload!
      encode(@payload)
    end

    def encode_signature
      return '' if @algorithm == ALG_NONE

      JWT::Base64.url_encode(JWT::Signature.sign(@algorithm, encoded_header_and_payload, @key))
    end

    def encode(data)
      JWT::Base64.url_encode(JWT::JSON.generate(data))
    end

    def combine(*parts)
      parts.join('.')
    end
  end
end
