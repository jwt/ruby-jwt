# frozen_string_literal: true

module JWT
  module JWK
    class RSA
      attr_reader :keypair

      BINARY = 2
      KTY    = 'RSA'.freeze

      def initialize(keypair)
        raise ArgumentError, 'keypair must be of type OpenSSL::PKey::RSA' unless keypair.is_a?(OpenSSL::PKey::RSA)

        @keypair = keypair
      end

      def private?
        keypair.private?
      end

      def public_key
        keypair.public_key
      end

      def kid
        sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer.new(public_key.n),
                                            OpenSSL::ASN1::Integer.new(public_key.e)])
        OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
      end

      def export(options = {})
        ret = {
          kty: KTY,
          n: encode_open_ssl_bn(public_key.n),
          e: encode_open_ssl_bn(public_key.e),
          kid: kid
        }

        return ret if options[:include_private] != true

        ret.merge(
          d: encode_open_ssl_bn(keypair.d),
          p: encode_open_ssl_bn(keypair.p),
          q: encode_open_ssl_bn(keypair.q),
          dp: encode_open_ssl_bn(keypair.dmp1),
          dq: encode_open_ssl_bn(keypair.dmq1),
          qi: encode_open_ssl_bn(keypair.iqmp)
        )
      end

      def encode_open_ssl_bn(key_part)
        ::Base64.urlsafe_encode64(key_part.to_s(BINARY), padding: false)
      end

      class << self
        def import(jwk_data)
          self.new(rsa_pkey(*jwk_attrs(jwk_data, :n, :e, :d, :p, :q, :dp, :dq, :qi)))
        end

        def jwk_attrs(jwk_data, *attrs)
          attrs.map do |attr|
            decode_open_ssl_bn(jwk_data[attr] || jwk_data[attr.to_s])
          end
        end

        def rsa_pkey(jwk_n, jwk_e, jwk_d, jwk_p, jwk_q, jwk_dp, jwk_dq, jwk_qi)
          raise JWT::JWKError, 'Key format is invalid for RSA' unless jwk_n && jwk_e

          key = OpenSSL::PKey::RSA.new

          if key.respond_to?(:set_key)
            key.set_key(jwk_n, jwk_e, jwk_d)
            key.set_factors(jwk_p, jwk_q) if jwk_p && jwk_q
            key.set_crt_params(jwk_dp, jwk_dq, jwk_qi) if jwk_dp && jwk_dq && jwk_qi
          else
            key.n = jwk_n
            key.e = jwk_e
            key.d = jwk_d if jwk_d
            key.p = jwk_p if jwk_p
            key.q = jwk_q if jwk_q
            key.dmp1 = jwk_dp if jwk_dp
            key.dmq1 = jwk_dq if jwk_dq
            key.iqmp = jwk_qi if jwk_qi
          end

          key
        end

        def decode_open_ssl_bn(jwk_data)
          return nil if jwk_data.nil?
          OpenSSL::BN.new(::Base64.urlsafe_decode64(jwk_data), BINARY)
        end
      end
    end
  end
end
