# frozen_string_literal: true

module JWT
  class EncodedToken
    # @private
    # Allow access to the unverified payload for claim verification.
    class ClaimsContext
      extend Forwardable

      def_delegators :@token, :header, :unverified_payload

      def initialize(token)
        @token = token
      end

      def payload
        unverified_payload
      end
    end
  end
end
