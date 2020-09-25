# frozen_string_literal: true

module JWT
  module JWK
    class HMAC < KeyAbstract
      KTY = 'oct'.freeze

      def initialize(keypair, kid = nil)
        raise ArgumentError, 'keypair must be of type String' unless keypair.is_a?(String)

        super
        @kid = kid || generate_kid(@keypair)
      end

      def private?
        true
      end

      def public_key
        nil
      end

      # See https://tools.ietf.org/html/rfc7517#appendix-A.3
      def export(options = {})
        ret = {
          kty: KTY,
          kid: kid
        }

        return ret unless private? && options[:include_private] == true

        ret.merge(
          k: keypair
        )
      end

      private

      def generate_kid(hmac_key)
        sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::UTF8String.new(hmac_key),
                                            OpenSSL::ASN1::UTF8String.new(KTY)])
        OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
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
