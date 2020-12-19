# frozen_string_literal: true

module JWT
  module JWK
    module HMAC
      class Secret
        CAPABILITIES = %i[verify sign].freeze

        attr_reader :kid

        def initialize(secret, kid = nil)
          raise ArgumentError, 'secret must be of type String' unless secret.is_a?(String)
          @secret = secret
          @kid = kid || generate_kid
        end

        # See https://tools.ietf.org/html/rfc7517#appendix-A.3
        def export(options = {})
          exported_key = {
            kty: HMAC::KTY,
            kid: kid
          }

          if options[:include_private]
            exported_key[:k] = secret
          end

          exported_key
        end

        def signing_key
          secret
        end

        alias verify_key signing_key

        def encryption_key
          raise ::JWT::JWKError, 'encryption_key is not available'
        end

        def decryption_key
          raise ::JWT::JWKError, 'decryption_key is not available'
        end

        def capabilities
          CAPABILITIES
        end

        private

        attr_reader :secret

        def generate_kid
          sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::UTF8String.new(secret),
                                              OpenSSL::ASN1::UTF8String.new(KTY)])
          OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
        end
      end
    end
  end
end
