# frozen_string_literal: true

module JWT
  module JWA
    module Wrappers
      class ExternalAlgorithm
        def initialize(jwa)
          @jwa = jwa
        end

        def header(signing_key:)
          jwa.header(signing_key: signing_key) if jwa.respond_to?(:header)
          { 'alg' => alg }
        end

        def valid_alg?(alg)
          jwa.valid_alg?(alg)
        end

        def alg
          jwa.alg
        end

        def verify(data:, signature:, verification_key:)
          jwa.verify(data: data, signature: signature, verification_key: verification_key)
        end

        def sign(data:, signing_key:)
          jwa.sign(data: data, signing_key: signing_key)
        end

        private

        attr_reader :jwa
      end
    end
  end
end
