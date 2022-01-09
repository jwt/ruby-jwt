# frozen_string_literal: true

require_relative 'decode_methods'

module JWT
  class Decode
    include DecodeMethods

    def initialize(token, options, &keyfinder)
      raise JWT::DecodeError, 'Nil JSON web token' unless token
      @token = token
      @options = options
      @keyfinder = keyfinder
    end

    def decode_segments
      validate_segment_count!
      if verify?
        verify_algo!
        verify_signature!
        verify_claims!(options)
      end
      raise JWT::DecodeError, 'Not enough or too many segments' unless header && payload
      [payload, header]
    end

    private

    attr_reader :options, :token, :keyfinder

    def verify_signature!
      return if none_algorithm?

      raise JWT::DecodeError, 'No verification key available' if Array(key).empty?

      return if Array(key).any? { |single_key| verify_signature_for?(algorithm_in_header, single_key) }

      raise JWT::VerificationError, 'Signature verification failed'
    end

    def verify_algo!
      raise JWT::IncorrectAlgorithm, 'An algorithm must be specified' if allowed_algorithms.empty?
      raise JWT::IncorrectAlgorithm, 'Token is missing alg header' unless algorithm_in_header
      raise JWT::IncorrectAlgorithm, 'Expected a different algorithm' unless options_includes_algo_in_header?
    end

    def key
      @key ||= use_keyfinder || resolve_key
    end

    def options_includes_algo_in_header?
      allowed_algorithms.any? { |alg| alg.casecmp(algorithm_in_header).zero? }
    end

    def allowed_algorithms
      Array(algorithm_from_options)
    end

    def algorithm_from_options
      # Order is very important - first check for string keys, next for symbols
      if options.key?('algorithm')
        options['algorithm']
      elsif options.key?(:algorithm)
        options[:algorithm]
      elsif options.key?('algorithms')
        options['algorithms']
      elsif options.key?(:algorithms)
        options[:algorithms]
      end
    end

    def use_keyfinder
      return nil unless keyfinder
      (keyfinder.arity == 2 ? keyfinder.call(header, payload) : keyfinder.call(header))
      # key can be of type [string, nil, OpenSSL::PKey, Array]
    end

    def none_algorithm?
      algorithm_in_header.casecmp('none').zero?
    end
  end
end
