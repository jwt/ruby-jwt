# frozen_string_literal: true

require_relative 'ec/private_key'
require_relative 'ec/public_key'

module JWT
  module JWK
    module EC
      include KeyAlgorithm

      KTY    = 'EC'.freeze
      KTYS   = [KTY, OpenSSL::PKey::EC].freeze

      class << self
        def create(keypair, kid = nil)
          if keypair.is_a?(OpenSSL::PKey::EC) && keypair.private_key?
            PrivateKey.new(keypair, kid)
          else
            public_key = keypair.is_a?(OpenSSL::PKey::EC) ? keypair.public_key : keypair
            PublicKey.new(public_key, kid)
          end
        end

        alias new create

        def import(jwk_data)
          # See https://tools.ietf.org/html/rfc7518#section-6.2.1 for an
          # explanation of the relevant parameters.

          jwk_crv, jwk_x, jwk_y, jwk_d, jwk_kid = jwk_attrs(jwk_data, %i[crv x y d kid])
          raise Jwt::JWKError, 'Key format is invalid for EC' unless jwk_crv && jwk_x && jwk_y

          create(ec_pkey(jwk_crv, jwk_x, jwk_y, jwk_d), jwk_kid)
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

        def ec_pkey(jwk_crv, jwk_x, jwk_y, jwk_d)
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
          key.private_key = OpenSSL::BN.new(decode_octets(jwk_d), 2) if jwk_d

          key
        end

        def decode_octets(jwk_data)
          ::JWT::Base64.url_decode(jwk_data)
        end
      end
    end
  end
end
