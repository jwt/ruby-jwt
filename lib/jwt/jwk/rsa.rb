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
          n: ::Base64.urlsafe_encode64(public_key.n.to_s(BINARY), padding: false),
          e: ::Base64.urlsafe_encode64(public_key.e.to_s(BINARY), padding: false),
          kid: kid
        }
      end

      def self.import(jwk_data)
        imported_key = OpenSSL::PKey::RSA.new
        if imported_key.respond_to?(:set_key)
          imported_key.set_key(OpenSSL::BN.new(::Base64.urlsafe_decode64(jwk_data[:n]), BINARY),
            OpenSSL::BN.new(::Base64.urlsafe_decode64(jwk_data[:e]), BINARY),
            nil)
        else
          imported_key.n = OpenSSL::BN.new(::Base64.urlsafe_decode64(jwk_data[:n]), BINARY)
          imported_key.e = OpenSSL::BN.new(::Base64.urlsafe_decode64(jwk_data[:e]), BINARY)
        end
        self.new(imported_key)
      end
    end
  end
end
