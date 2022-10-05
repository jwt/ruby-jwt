# frozen_string_literal: true

module JWT
  module Algos
    class AlgoWrapper
      attr_reader :alg, :cls

      def initialize(alg, cls)
        @alg = alg
        @cls = cls
      end

      def valid_alg?(alg_to_check)
        alg.casecmp(alg_to_check)&.zero? == true
      end

      def sign(data:, signing_key:)
        cls.sign(alg, data, signing_key)
      end

      def verify(data:, signature:, verification_key:)
        cls.verify(alg, verification_key, data, signature)
      rescue OpenSSL::PKey::PKeyError # These should be moved to the algorithms that actually need this, but left here to ensure nothing will break.
        raise JWT::VerificationError, 'Signature verification raised'
      ensure
        OpenSSL.errors.clear
      end
    end
  end
end
