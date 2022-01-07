# frozen_string_literal: true

require_relative 'decode_behaviour'

module JWT
  class DecodeToken
    include DecodeBehaviour

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

    def verify?
      options[:verify] != false
    end

    def key
      @key ||=
        if options[:jwks]
          ::JWT::JWK::KeyFinder.new(jwks: options[:jwks]).key_for(header['kid'])
        elsif (x5c_options = options[:x5c])
          ::JWT::X5cKeyFinder.new(x5c_options[:root_certificates], x5c_options[:crls]).from(header['x5c'])
        else
          options[:key]
        end
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

    def verify_signature_for?(algorithm, key)
      if algorithm.is_a?(String)
        raise JWT::DecodeError, 'No verification key available' unless key

        Array(key).any? { |k| Signature.verify(algorithm, k, signing_input, signature) }
      else
        algorithm.verify(signing_input, signature, key: key, header: header, payload: payload)
      end
    end
  end
end
