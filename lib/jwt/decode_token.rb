# frozen_string_literal: true

require_relative 'decode_methods'

module JWT
  class DecodeToken
    include DecodeMethods

    def initialize(token, options = {})
      raise ArgumentError, 'Provided token is not a String object' unless token.is_a?(String)

      @token   = token
      @options = options
    end

    def decoded_segments
      validate_segment_count!

      if verify?
        verify_alg_header!
        verify_signature!
        verify_claims!(options)
      end

      [payload, header]
    end

    private

    attr_reader :token, :options

    def algorithms
      @algorithms ||= Array(options[:algorithms])
    end

    def key
      @key ||= resolve_key
    end

    def verify_alg_header!
      return unless valid_algorithms.empty?

      raise JWT::IncorrectAlgorithm, 'Expected a different algorithm'
    end

    def valid_algorithms
      @valid_algorithms ||= algorithms.select do |algorithm|
        if algorithm.is_a?(String)
          header['alg'] == algorithm
        else
          algorithm.valid_alg?(header['alg'])
        end
      end
    end

    def verify_signature!
      return if valid_algorithms.any? { |algorithm| verify_signature_for?(algorithm, key) }

      raise JWT::VerificationError, 'Signature verification failed'
    end
  end
end
