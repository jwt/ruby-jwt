# frozen_string_literal: true

module JWT
  module JWA
    # @api private
    class VerifierContext
      attr_reader :jwa

      def initialize(jwa:, keys:)
        @jwa = jwa
        @keys = Array(keys)
      end

      def verify(*args, **kwargs)
        errors = []
        verified = @keys.any? do |key|
          @jwa.verify(*args, **kwargs, verification_key: key)
        rescue VerificationError => e
          errors << e
          false
        end
        raise errors.first if !verified && !errors.empty? && errors.size == @keys.size

        verified
      end
    end
  end
end
