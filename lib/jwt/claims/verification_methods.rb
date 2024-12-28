# frozen_string_literal: true

module JWT
  module Claims
    # Provides methods to verify the claims of a token.
    module VerificationMethods
      # Verifies the claims of the token.
      # @param options [Array<Symbol>, Hash] the claims to verify.
      # @raise [JWT::DecodeError] if the claims are invalid.
      def verify_claims!(*options)
        Verifier.verify!(self, *options)
      end

      # Returns the errors of the claims of the token.
      # @param options [Array<Symbol>, Hash] the claims to verify.
      # @return [Array<Symbol>] the errors of the claims.
      def claim_errors(*options)
        Verifier.errors(self, *options)
      end

      # Returns whether the claims of the token are valid.
      # @param options [Array<Symbol>, Hash] the claims to verify.
      # @return [Boolean] whether the claims are valid.
      def valid_claims?(*options)
        claim_errors(*options).empty?
      end
    end
  end
end
