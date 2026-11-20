# frozen_string_literal: true

module JWT
  module Claims
    # The NotBefore class is responsible for validating the 'nbf' (Not Before) claim in a JWT token.
    class NotBefore
      # Initializes a new NotBefore instance.
      #
      # @param leeway [Integer] the amount of leeway (in seconds) to allow when validating the 'nbf' claim. Defaults to 0.
      def initialize(leeway:)
        @leeway = leeway || 0
      end

      # Verifies the 'nbf' (Not Before) claim in the JWT token.
      #
      # @param context [Object] the context containing the JWT payload.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::InvalidPayload] if the 'nbf' claim is not a Numeric.
      # @raise [JWT::ImmatureSignature] if the 'nbf' claim has not been reached.
      # @return [nil]
      def verify!(context:, **_args)
        return unless context.payload.is_a?(Hash)
        return unless context.payload.key?('nbf')

        nbf = context.payload['nbf']
        raise JWT::InvalidPayload, "nbf claim must be a Numeric value but it is a #{nbf.class}" unless nbf.is_a?(::Numeric)
        raise JWT::ImmatureSignature, 'Signature nbf has not been reached' if nbf.to_i > (Time.now.to_i + leeway)
      end

      private

      attr_reader :leeway
    end
  end
end
