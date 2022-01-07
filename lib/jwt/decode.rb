# frozen_string_literal: true

require_relative 'decode_methods'

module JWT
  class Decode
    include DecodeMethods
    def initialize(token, key, verify, options, &keyfinder)
      raise(JWT::DecodeError, 'Nil JSON web token') unless token
      @token = token
      @key = key
      @options = options
      @verify = verify
      @keyfinder = keyfinder
    end

    def decode_segments
      validate_segment_count!
      if verify?
        verify_algo
        verify_signature
        verify_claims!(options)
      end
      raise(JWT::DecodeError, 'Not enough or too many segments') unless header && payload
      [payload, header]
    end

    private

    attr_reader :options, :token

    def verify?
      @verify != false
    end

    def verify_signature
      return unless key || verify?

      return if none_algorithm?

      raise JWT::DecodeError, 'No verification key available' unless key

      return if Array(key).any? { |k| verify_signature_for?(algorithm, k) }

      raise(JWT::VerificationError, 'Signature verification failed')
    end

    def verify_algo
      raise(JWT::IncorrectAlgorithm, 'An algorithm must be specified') if allowed_algorithms.empty?
      raise(JWT::IncorrectAlgorithm, 'Token is missing alg header') unless algorithm
      raise(JWT::IncorrectAlgorithm, 'Expected a different algorithm') unless options_includes_algo_in_header?
    end

    def key
      @key ||= (@keyfinder && find_key(&@keyfinder)) || resolve_key
    end

    def options_includes_algo_in_header?
      allowed_algorithms.any? { |alg| alg.casecmp(algorithm).zero? }
    end

    def allowed_algorithms
      # Order is very important - first check for string keys, next for symbols
      algos = if options.key?('algorithm')
        options['algorithm']
      elsif options.key?(:algorithm)
        options[:algorithm]
      elsif options.key?('algorithms')
        options['algorithms']
      elsif options.key?(:algorithms)
        options[:algorithms]
      else
        []
      end
      Array(algos)
    end

    def find_key(&keyfinder)
      key = (keyfinder.arity == 2 ? yield(header, payload) : yield(header))
      # key can be of type [string, nil, OpenSSL::PKey, Array]
      return key if key && !Array(key).empty?

      raise JWT::DecodeError, 'No verification key available'
    end

    def none_algorithm?
      algorithm.casecmp('none').zero?
    end

    def algorithm
      header['alg']
    end
  end
end
