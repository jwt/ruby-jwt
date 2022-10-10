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
        exported_hash = common_parameters.merge({ kty: KTY })

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

      def [](key)
        if key.to_sym == :k || key.to_sym == :kty
          raise ArgumentError, 'cannot access cryptographic key attributes'
        end

        super(key)
      end

      def []=(key, value)
        if key.to_sym == :k || key.to_sym == :kty
          raise ArgumentError, 'cannot access cryptographic key attributes'
        end

        super(key, value)
      end

      class << self
        def import(jwk_data)
          parameters = jwk_data.transform_keys(&:to_sym)
          jwk_kty = parameters.delete(:kty) # Will be re-added upon export
          jwk_k   = parameters.delete(:k)

          raise JWT::JWKError, "Incorrect 'kty' value: #{jwk_kty}, expected #{KTY}" unless jwk_kty == KTY
          raise JWT::JWKError, 'Key format is invalid for HMAC' unless jwk_k

          new(jwk_k, common_parameters: parameters)
        end
      end
    end
  end
end
