# frozen_string_literal: true

require_relative 'algos'
require_relative 'claims_validator'

module JWT
  class Encode
    def initialize(options)
      @options = options
      @payload = options[:payload]
      @key     = options[:key]

      if (algo = options[:algorithm]).respond_to?(:sign)
        @algorithm = algo
      else
        _, @alg = Algos.find(algo)
      end

      @headers = (options[:headers] || {}).transform_keys(&:to_s)

      headers['alg'] = algorithm ? algorithm.alg : alg
    end

    def segments
      validate_claims!
      combine(encoded_header_and_payload, encoded_signature)
    end

    private

    attr_reader :payload, :headers, :options, :algorithm, :key, :alg

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
      encode(headers)
    end

    def encode_payload
      if (encode_proc = options[:encode_payload_proc])
        return encode_proc.call(payload)
      end

      encode(payload)
    end

    def encode_signature
      Base64.urlsafe_encode64(signature, padding: false)
    end

    def signature
      return algorithm.sign(encoded_header_and_payload, key: key) if algorithm

      JWT::Signature.sign(alg, encoded_header_and_payload, key)
    end

    def validate_claims!
      return unless payload.is_a?(Hash)

      ClaimsValidator.new(payload).validate!
    end

    def encode(data)
      Base64.urlsafe_encode64(JWT::JSON.generate(data), padding: false)
    end

    def combine(*parts)
      parts.join('.')
    end
  end
end
