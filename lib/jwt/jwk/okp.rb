# frozen_string_literal: true

module JWT
  module JWK
    # https://tools.ietf.org/html/rfc8037
    class OKP < KeyBase
      BINARY = 2
      KTY    = 'OKP'.freeze
      KTYS   = [KTY, RbNaCl::Signatures::Ed25519::SigningKey, RbNaCl::Signatures::Ed25519::VerifyKey]

      attr_reader :kid

      def initialize(key, kid = nil)
        case key
        when RbNaCl::Signatures::Ed25519::SigningKey
          @signing_key = key
          @verify_key = key.verify_key
        when RbNaCl::Signatures::Ed25519::VerifyKey
          @verify_key = key
        else
          raise ArgumentError, 'key must be of type RbNaCl::Signatures::Ed25519::SigningKey or RbNaCl::Signatures::Ed25519::VerifyKey' 
        end

        @kid = kid
        
        super
      end
    end
  end
end