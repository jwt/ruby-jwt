# frozen_string_literal: true

module JWT
  module JWK
    class HMAC < KeyBase
      KTY = 'oct'.freeze
      KTYS = [KTY, String].freeze

      attr_reader :secret

      alias verify_key secret
      alias signing_key secret

      def initialize(secret, kid = nil)
        raise ArgumentError, 'secret must be of type String' unless secret.is_a?(String)
        @secret = secret
        @kid = kid
      end

      def private?
        true
      end

      def public_key
        nil
      end

      def kid
        @kid ||= generate_kid
      end

      def members
        {
          kty: KTY,
          k: signing_key
        }
      end

      # See https://tools.ietf.org/html/rfc7517#appendix-A.3
      def export(options = {})
        exported_hash = {
          kty: KTY,
          kid: kid
        }

        return exported_hash unless private? && options[:include_private] == true

        exported_hash.merge(
          k: signing_key
        )
      end

      private

      def generate_kid
        Thumbprint.new(self).to_s
      end

      class << self
        def import(jwk_data)
          jwk_k = jwk_data[:k] || jwk_data['k']
          jwk_kid = jwk_data[:kid] || jwk_data['kid']

          raise JWT::JWKError, 'Key format is invalid for HMAC' unless jwk_k

          self.new(jwk_k, jwk_kid)
        end
      end
    end
  end
end
