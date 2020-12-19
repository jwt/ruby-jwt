# frozen_string_literal: true

module JWT
  module JWK
    module RSA
      class PublicKey
        CAPABILITIES = %i[verify encrypt decrypt].freeze

        attr_reader :kid

        def initialize(key, kid = nil)
          raise ArgumentError, 'key must be of type OpenSSL::PKey::RSA' unless key.is_a?(OpenSSL::PKey::RSA)
          @key = key
          @kid = kid || generate_kid
        end

        def export(_options = {})
          {
            kty: RSA::KTY,
            n: ::JWT::JWK.encode_open_ssl_bn(key.n),
            e: ::JWT::JWK.encode_open_ssl_bn(key.e),
            kid: kid
          }
        end

        def keypair
          warn('Deprecated: The #keypair method for JWK classes is deprecated. ' \
               'Use the use-case specific #verify_key or #signing_key methods')
          key
        end

        def private?
          warn('Deprecated: The #private? method for JWK classes is deprecated. ' \
               'To get key capabilities use the #capabilites method')
          false
        end

        def capabilities
          CAPABILITIES
        end

        def signing_key
          raise ::JWT::JWKError, 'signing_key is not available'
        end

        def verify_key
          key
        end

        alias encryption_key verify_key
        alias decryption_key verify_key

        private

        attr_reader :key

        def generate_kid
          sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer.new(key.n),
                                              OpenSSL::ASN1::Integer.new(key.e)])
          OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
        end
      end
    end
  end
end
