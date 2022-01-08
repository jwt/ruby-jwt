# frozen_string_literal: true

require_relative 'algos'
require_relative 'claims_validator'

module JWT
  class Encode
    def initialize(options)
      @options = options
      @payload = options[:payload]
      @key     = options[:key]

      if (algo = options[:algorithm]).is_a?(String) || algo.nil?
        _, @alg = Algos.find(algo)
      else
        @algorithm = algo
      end

      @headers = (options[:headers] || {}).transform_keys(&:to_s)

      headers['alg'] = algorithm ? algorithm.alg : alg
    end

    def segments
      ClaimsValidator.new(payload).validate! if payload.is_a?(Hash)

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
      return options[:encode_payload_proc].call(payload) if options[:encode_payload_proc]

      encode(payload)
    end

    def encode_signature
      Base64.urlsafe_encode64(signature, padding: false)
    end

    def signature
      return algorithm.sign(encoded_header_and_payload, key: key) if algorithm

      JWT::Signature.sign(alg, encoded_header_and_payload, key)
    end

    def encode(data)
      Base64.urlsafe_encode64(JWT::JSON.generate(data), padding: false)
    end

    def combine(*parts)
      parts.join('.')
    end
  end
end
