# frozen_string_literal: true

require 'openssl'

require_relative 'jwa/signing_algorithm'
require_relative 'jwa/ecdsa'
require_relative 'jwa/hmac'
require_relative 'jwa/none'
require_relative 'jwa/ps'
require_relative 'jwa/rsa'
require_relative 'jwa/unsupported'

module JWT
  # The JWA module contains all supported algorithms.
  module JWA
    # @api private
    class VerifierContext
      def initialize(jwa:, keys:)
        @jwa = jwa
        @keys = Array(keys)
      end

      def verify(*args, **kwargs)
        @keys.any? do |key|
          @jwa.verify(*args, **kwargs, verification_key: key)
        end
      end
    end

    # @api private
    class SignerContext
      def initialize(jwa:, key:)
        @jwa = jwa
        @key = key
      end

      def sign(*args, **kwargs)
        @jwa.sign(*args, **kwargs, signing_key: @key)
      end

      def jwa_header
        @jwa.header
      end
    end

    class << self
      # @api private
      def resolve(algorithm)
        return find(algorithm) if algorithm.is_a?(String) || algorithm.is_a?(Symbol)

        raise ArgumentError, 'Algorithm must be provided' if algorithm.nil?

        raise ArgumentError, 'Custom algorithms are required to include JWT::JWA::SigningAlgorithm' unless algorithm.is_a?(SigningAlgorithm)

        algorithm
      end

      # @api private
      def resolve_and_sort(algorithms:, preferred_algorithm:)
        Array(algorithms).map { |alg| JWA.resolve(alg) }
                         .partition { |alg| alg.valid_alg?(preferred_algorithm) }
                         .flatten
      end

      # @api private
      def create_signer(algorithm:, key:)
        return key if key.is_a?(JWK::KeyBase)

        SignerContext.new(jwa: resolve(algorithm), key: key)
      end

      # @api private
      def create_verifiers(algorithms:, keys:, preferred_algorithm:)
        jwks, other_keys = keys.partition { |key| key.is_a?(JWK::KeyBase) }

        jwks + resolve_and_sort(algorithms: algorithms,
                                preferred_algorithm: preferred_algorithm)
               .map { |jwa| VerifierContext.new(jwa: jwa, keys: other_keys) }
      end
    end
  end
end
