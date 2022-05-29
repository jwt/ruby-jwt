# frozen_string_literal: true

module JWT
  module JWK
    class HMAC < KeyBase
      KTY  = 'oct'
      KTYS = [KTY, String].freeze

      attr_reader :signing_key

      def initialize(signing_key, options = {})
        raise ArgumentError, 'signing_key must be of type String' unless signing_key.is_a?(String)

        @signing_key = signing_key
        super(options)
      end

      def private?
        true
      end

      def public_key
        nil
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

      def members
        {
          kty: KTY,
          k: signing_key
        }
      end

      alias keypair signing_key # for backwards compatibility

      def key_digest
        sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::UTF8String.new(signing_key),
                                            OpenSSL::ASN1::UTF8String.new(KTY)])
        OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
      end

      class << self
        def import(jwk_data)
          jwk_k = jwk_data[:k] || jwk_data['k']
          jwk_kid = jwk_data[:kid] || jwk_data['kid']

          raise JWT::JWKError, 'Key format is invalid for HMAC' unless jwk_k

          new(jwk_k, kid: jwk_kid)
        end
      end
    end
  end
end
