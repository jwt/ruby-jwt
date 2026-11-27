# frozen_string_literal: true

module JWT
  module Claims
    # The Issuer class is responsible for validating the issuer claim ('iss') in a JWT token.
    class Issuer
      # Initializes a new Issuer instance.
      #
      # @param issuers [String, Symbol, Array<String, Symbol>] the expected issuer(s) for the JWT token.
      def initialize(issuers:)
        @issuers = Array(issuers).map { |item| item.is_a?(Symbol) ? item.to_s : item }
      end

      # Verifies the issuer claim ('iss') in the JWT token.
      #
      # @param context [Object] the context containing the JWT payload.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::InvalidIssuerError] if the issuer claim is missing, is not a String or matches none of the expected issuers.
      #   A payload that is not a Hash has no issuer claim. The expected issuers are only matched against a String.
      # @return [nil]
      def verify!(context:, **_args)
        iss = context.payload['iss'] if context.payload.is_a?(Hash)
        return if iss.is_a?(String) && expected_issuer?(iss)

        raise JWT::InvalidIssuerError, "Invalid issuer. Expected #{issuers}, received #{iss || '<none>'}"
      end

      private

      attr_reader :issuers

      def expected_issuer?(iss)
        case iss
        when *issuers then true
        else false
        end
      end
    end
  end
end
