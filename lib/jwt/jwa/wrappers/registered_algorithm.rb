# frozen_string_literal: true

module JWT
  module JWA
    module Wrappers
      class RegisteredAlgorithm
        attr_reader :alg

        def initialize(alg, jwa)
          @alg = alg
          @jwa = jwa
        end

        def valid_alg?(alg_to_check)
          alg&.casecmp(alg_to_check)&.zero? == true
        end

        def sign(data:, signing_key:)
          jwa.sign(alg, data, signing_key)
        end

        def verify(data:, signature:, verification_key:)
          jwa.verify(alg, verification_key, data, signature)
        end

        def header(signing_key:)
          jwa.header(alg, signing_key)
        end

        private

        attr_reader :jwa
      end
    end
  end
end
