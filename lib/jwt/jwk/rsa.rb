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

      def export
        {
          kty: KTY,
          n: encode_open_ssl_bn(public_key.n),
          e: encode_open_ssl_bn(public_key.e),
          kid: kid
        }
      end

      def encode_open_ssl_bn(key_part)
        ::Base64.urlsafe_encode64(key_part.to_s(BINARY), padding: false)
      end

      def self.import(jwk_data)
        jwk_n = jwk_data[:n] || jwk_data['n']
        jwk_e = jwk_data[:e] || jwk_data['e']

        raise JWT::JWKError, 'Key format is invalid for RSA' unless jwk_n && jwk_e

        self.new(rsa_pkey(jwk_n, jwk_e))
      end

      def self.rsa_pkey(jwk_n, jwk_e)
        key = OpenSSL::PKey::RSA.new
        key_n = decode_open_ssl_bn(jwk_n)
        key_e = decode_open_ssl_bn(jwk_e)

        if key.respond_to?(:set_key)
          key.set_key(key_n, key_e, nil)
        else
          key.n = key_n
          key.e = key_e
        end

        key
      end

      def self.decode_open_ssl_bn(jwk_data)
        OpenSSL::BN.new(::Base64.urlsafe_decode64(jwk_data), BINARY)
      end
    end
  end
end
