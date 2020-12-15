# frozen_string_literal: true

module JWT
  module JWK
    class KeyBase
      def self.inherited(klass)
        ::JWT::JWK.classes << klass
      end

      def keypair
        signing_key || verify_key
      end

      def public_key
        verify_key
      end

      def private_key
        signing_key
      end
    end
  end
end
