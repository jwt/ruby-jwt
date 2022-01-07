# frozen_string_literal: true

require_relative './algos'
require_relative './claims_validator'

# JWT::Encode module
module JWT
  # Encoding logic for JWT
  class Encode
    ALG_NONE = 'none'.freeze
    ALG_KEY  = 'alg'.freeze

    def initialize(options)
      @options = options
      @payload = options[:payload]
      @key = options[:key]

      if (@algorithm_implementation = options[:algorithm_implementation]).nil?
        _, @algorithm = Algos.find(options[:algorithm])
      else
        @algorithm = @algorithm_implementation.alg
      end

      @headers = options[:headers].each_with_object({}) { |(key, value), headers| headers[key.to_s] = value }
    end

    def segments
      @segments ||= combine(encoded_header_and_payload, encoded_signature)
    end

    private

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
      @headers[ALG_KEY] = @algorithm
      encode(@headers)
    end

    def encode_payload
      if @payload && @payload.is_a?(Hash)
        ClaimsValidator.new(@payload).validate!
      end

      return @options[:encode_payload_proc].call(@payload) unless @options[:encode_payload_proc].nil?

      encode(@payload)
    end

    def encode_signature
      return '' if @algorithm == ALG_NONE

      Base64.urlsafe_encode64(signature, padding: false)
    end

    def signature
      return @algorithm_implementation.sign(encoded_header_and_payload, key: @key) if @algorithm_implementation

      JWT::Signature.sign(@algorithm, encoded_header_and_payload, @key)
    end

    def encode(data)
      Base64.urlsafe_encode64(JWT::JSON.generate(data), padding: false)
    end

    def combine(*parts)
      parts.join('.')
    end
  end
end
