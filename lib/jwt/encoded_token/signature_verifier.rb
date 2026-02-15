# frozen_string_literal: true

module JWT
  class EncodedToken
    # @private
    # Handles signature verification logic.
    class SignatureVerifier
      def initialize(token)
        @token = token
      end

      def verify(algorithm:, key: nil, key_finder: nil)
        raise ArgumentError, 'Provide either key or key_finder, not both or neither' if key.nil? == key_finder.nil?

        keys = Array(key || key_finder.call(@token))
        verifiers = JWA.create_verifiers(algorithms: algorithm, keys: keys, preferred_algorithm: @token.header['alg'])

        raise JWT::VerificationError, 'No algorithm provided' if verifiers.empty?

        verifiers.any? { |jwa| jwa.verify(data: @token.signing_input, signature: @token.signature) }
      end
    end
  end
end
