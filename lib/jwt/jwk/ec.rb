# frozen_string_literal: true

module JWT
  module JWK
    class EC
      extend Forwardable
      def_delegators :@keypair, :private?, :public_key

      attr_reader :keypair

      KTY    = 'EC'.freeze
      BINARY = 2

      def initialize(keypair)
        raise ArgumentError, 'keypair must be of type OpenSSL::PKey::EC' unless keypair.is_a?(OpenSSL::PKey::EC)

        @keypair = keypair
      end

      def export
        crv, x_octets, y_octets = keypair_components
        sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(x_octets, BINARY)),
                                            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(y_octets, BINARY))])
        kid = OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
        {
          kty: KTY,
          crv: crv,
          x: encode_octets(x_octets),
          y: encode_octets(y_octets),
          kid: kid
        }
      end

      private

      def keypair_components
        encoded_point = keypair.public_key.to_bn.to_s(BINARY)
        case keypair.group.curve_name
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
          raise "Unsupported curve '#{keypair.group.curve_name}'"
        end
        [crv, x_octets, y_octets]
      end

      def encode_octets(octets)
        ::Base64.urlsafe_encode64(octets, padding: false)
      end

      def encode_open_ssl_bn(key_part)
        ::Base64.urlsafe_encode64(key_part.to_s(BINARY), padding: false)
      end

      class << self
        def import(jwk_data)
          # See https://tools.ietf.org/html/rfc7518#section-6.2.1 for an
          # explanation of the relevant parameters.

          jwk_crv, jwk_x, jwk_y = jwk_attrs(jwk_data, %i[crv x y])
          raise Jwt::JWKError, 'Key format is invalid for EC' unless jwk_crv && jwk_x && jwk_y

          new(ec_pkey(jwk_crv, jwk_x, jwk_y))
        end

        def to_openssl_curve(crv)
          # The JWK specs and OpenSSL use different names for the same curves.
          # See https://tools.ietf.org/html/rfc5480#section-2.1.1.1 for some
          # pointers on different names for common curves.
          case crv
          when 'P-256' then 'prime256v1'
          when 'P-384' then 'secp384r1'
          when 'P-521' then 'secp521r1'
          else raise JWT::JWKError, 'Invalid curve provided'
          end
        end

        private

        def jwk_attrs(jwk_data, attrs)
          attrs.map do |attr|
            jwk_data[attr] || jwk_data[attr.to_s]
          end
        end

        def ec_pkey(jwk_crv, jwk_x, jwk_y)
          curve = to_openssl_curve(jwk_crv)

          x_octets = decode_octets(jwk_x)
          y_octets = decode_octets(jwk_y)

          key = OpenSSL::PKey::EC.new(curve)

          # The details of the `Point` instantiation are covered in:
          # - https://docs.ruby-lang.org/en/2.4.0/OpenSSL/PKey/EC.html
          # - https://www.openssl.org/docs/manmaster/man3/EC_POINT_new.html
          # - https://tools.ietf.org/html/rfc5480#section-2.2
          # - https://www.secg.org/SEC1-Ver-1.0.pdf
          # Section 2.3.3 of the last of these references specifies that the
          # encoding of an uncompressed point consists of the byte `0x04` followed
          # by the x value then the y value.
          point = OpenSSL::PKey::EC::Point.new(
            OpenSSL::PKey::EC::Group.new(curve),
            OpenSSL::BN.new([0x04, x_octets, y_octets].pack('Ca*a*'), 2)
          )

          key.public_key = point

          key
        end

        def decode_octets(jwk_data)
          ::Base64.urlsafe_decode64(jwk_data)
        end

        def decode_open_ssl_bn(jwk_data)
          OpenSSL::BN.new(::Base64.urlsafe_decode64(jwk_data), BINARY)
        end
      end
    end
  end
end
