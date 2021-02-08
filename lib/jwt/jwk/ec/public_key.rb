# frozen_string_literal: true

module JWT
  module JWK
    module EC
      class PublicKey
        CAPABILITIES = %i[verify].freeze
        BINARY = 2

        attr_reader :kid, :verify_key

        def initialize(point, kid = nil)
          raise ArgumentError, 'key must be of type OpenSSL::PKey::EC::Point' unless point.is_a?(OpenSSL::PKey::EC::Point)
          @point = point
          @kid = kid || generate_kid
          @verify_key = OpenSSL::PKey::EC.new(point.group).tap { |ec| ec.public_key = point }
        end

        def export(_options = {})
          crv, x_octets, y_octets = keypair_components
          {
            kty: EC::KTY,
            crv: crv,
            x: ::JWT::Base64.url_encode(x_octets),
            y: ::JWT::Base64.url_encode(y_octets),
            kid: kid
          }
        end

        def capabilities
          CAPABILITIES
        end

        def encryption_key
          raise ::JWT::JWKError, 'encryption_key is not available'
        end

        def decryption_key
          raise ::JWT::JWKError, 'decryption_key is not available'
        end

        def signing_key
          raise ::JWT::JWKError, 'signing_key is not available'
        end

        private

        attr_reader :point

        def generate_kid
          _crv, x_octets, y_octets = keypair_components
          sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(x_octets, BINARY)),
                                              OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(y_octets, BINARY))])
          OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
        end

        def keypair_components
          encoded_point = point.to_bn.to_s(BINARY)
          case point.group.curve_name
          when 'prime256v1'
            crv = 'P-256'
            x_octets, y_octets = encoded_point.unpack('xa32a32')
          when 'secp384r1'
            crv = 'P-384'
            x_octets, y_octets = encoded_point.unpack('xa48a48')
          when 'secp521r1'
            crv = 'P-521'
            x_octets, y_octets = encoded_point.unpack('xa66a66')
          else
            raise Jwt::JWKError, "Unsupported curve '#{point.group.curve_name}'"
          end
          [crv, x_octets, y_octets]
        end
      end
    end
  end
end
