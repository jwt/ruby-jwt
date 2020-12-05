# frozen_string_literal: true

module JWT
  module JWK
    # https://tools.ietf.org/html/rfc8037
    class OKP < KeyBase
      BINARY = 2
      KTY    = 'OKP'.freeze
      KTYS   = [KTY,
                RbNaCl::Signatures::Ed25519::SigningKey,
                RbNaCl::Signatures::Ed25519::VerifyKey].freeze

      ED25519 = 'Ed25519'.freeze

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

      def private?
        !@signing_key.nil?
      end

      def kid
        @kid ||= generate_kid
      end

      def generate_kid
        Thumbprint.new(self).to_s
      end

      def members
        {
          kty: KTY,
          crv: ED25519,
          x: ::JWT::Base64.url_encode(@verify_key.to_bytes)
        }
      end

      def export(options = {})
        exported_hash = members.merge(kid: kid)
        return exported_hash unless private? && options[:include_private] == true

        append_private_parts(exported_hash)
      end

      private

      def append_private_parts(the_hash)
        the_hash.merge(
          d: ::JWT::Base64.url_encode(@signing_key.to_bytes)
        )
      end
    end
  end
end
