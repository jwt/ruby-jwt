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
    class << self
      # @api private
      def resolve(algorithm)
        return find(algorithm) if algorithm.is_a?(String) || algorithm.is_a?(Symbol)

        raise ArgumentError, 'Custom algorithms are required to include JWT::JWA::SigningAlgorithm' unless algorithm.is_a?(SigningAlgorithm)

        algorithm
      end

      # @api private
      def resolve_and_sort(algorithms:, preferred_algorithm:)
        algs = Array(algorithms).map { |alg| JWA.resolve(alg) }
        algs.partition { |alg| alg.valid_alg?(preferred_algorithm) }.flatten
      end

      # @api private
      class VerificationContext
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
      def create_verifiers(algorithms:, keys:, preferred_algorithm:)
        jwks, other_keys = keys.partition { |key| key.is_a?(JWK::KeyBase) }

        jwks + resolve_and_sort(algorithms: algorithms,
                                preferred_algorithm: preferred_algorithm)
               .map { |jwa| VerificationContext.new(jwa: jwa, keys: other_keys) }
      end
    end
  end
end
