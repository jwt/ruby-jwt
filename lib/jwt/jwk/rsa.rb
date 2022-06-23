# frozen_string_literal: true

module JWT
  module JWK
    class RSA < KeyBase
      BINARY = 2
      KTY    = 'RSA'
      KTYS   = [KTY, OpenSSL::PKey::RSA].freeze
      RSA_KEY_ELEMENTS = %i[n e d p q dp dq qi].freeze

      attr_reader :keypair

      def initialize(keypair, options = {})
        raise ArgumentError, 'keypair must be of type OpenSSL::PKey::RSA' unless keypair.is_a?(OpenSSL::PKey::RSA)

        @keypair = keypair

        super(options)
      end

      def private?
        keypair.private?
      end

      def public_key
        keypair.public_key
      end

      def export(options = {})
        exported_hash = members.merge(kid: kid)

        return exported_hash unless private? && options[:include_private] == true

        append_private_parts(exported_hash)
      end

      def members
        {
          kty: KTY,
          n: encode_open_ssl_bn(public_key.n),
          e: encode_open_ssl_bn(public_key.e)
        }
      end

      def key_digest
        sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer.new(public_key.n),
                                            OpenSSL::ASN1::Integer.new(public_key.e)])
        OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
      end

      private

      def append_private_parts(the_hash)
        the_hash.merge(
          d: encode_open_ssl_bn(keypair.d),
          p: encode_open_ssl_bn(keypair.p),
          q: encode_open_ssl_bn(keypair.q),
          dp: encode_open_ssl_bn(keypair.dmp1),
          dq: encode_open_ssl_bn(keypair.dmq1),
          qi: encode_open_ssl_bn(keypair.iqmp)
        )
      end

      def encode_open_ssl_bn(key_part)
        ::JWT::Base64.url_encode(key_part.to_s(BINARY))
      end

      class << self
        def import(jwk_data)
          pkey_params = jwk_attributes(jwk_data, *RSA_KEY_ELEMENTS) do |value|
            decode_open_ssl_bn(value)
          end
          new(rsa_pkey(pkey_params), kid: jwk_attributes(jwk_data, :kid)[:kid])
        end

        private

        def jwk_attributes(jwk_data, *attributes)
          attributes.each_with_object({}) do |attribute, hash|
            value = jwk_data[attribute] || jwk_data[attribute.to_s]
            value = yield(value) if block_given?
            hash[attribute] = value
          end
        end

        def rsa_pkey(rsa_parameters)
          raise JWT::JWKError, 'Key format is invalid for RSA' unless rsa_parameters[:n] && rsa_parameters[:e]

          create_rsa_key(rsa_parameters)
        end

        if ::JWT.openssl_3?
          ASN1_SEQUENCE = %i[n e d p q dp dq qi].freeze
          def create_rsa_key(rsa_parameters)
            sequence = ASN1_SEQUENCE.each_with_object([]) do |key, arr|
              next if rsa_parameters[key].nil?

              arr << OpenSSL::ASN1::Integer.new(rsa_parameters[key])
            end

            if sequence.size > 2 # For a private key
              sequence.unshift(OpenSSL::ASN1::Integer.new(0))
            end

            OpenSSL::PKey::RSA.new(OpenSSL::ASN1::Sequence(sequence).to_der)
          end
        elsif OpenSSL::PKey::RSA.new.respond_to?(:set_key)
          def create_rsa_key(rsa_parameters)
            OpenSSL::PKey::RSA.new.tap do |rsa_key|
              rsa_key.set_key(rsa_parameters[:n], rsa_parameters[:e], rsa_parameters[:d])
              rsa_key.set_factors(rsa_parameters[:p], rsa_parameters[:q]) if rsa_parameters[:p] && rsa_parameters[:q]
              rsa_key.set_crt_params(rsa_parameters[:dp], rsa_parameters[:dq], rsa_parameters[:qi]) if rsa_parameters[:dp] && rsa_parameters[:dq] && rsa_parameters[:qi]
            end
          end
        else
          def create_rsa_key(rsa_parameters) # rubocop:disable Metrics/AbcSize
            OpenSSL::PKey::RSA.new.tap do |rsa_key|
              rsa_key.n = rsa_parameters[:n]
              rsa_key.e = rsa_parameters[:e]
              rsa_key.d = rsa_parameters[:d] if rsa_parameters[:d]
              rsa_key.p = rsa_parameters[:p] if rsa_parameters[:p]
              rsa_key.q = rsa_parameters[:q] if rsa_parameters[:q]
              rsa_key.dmp1 = rsa_parameters[:dp] if rsa_parameters[:dp]
              rsa_key.dmq1 = rsa_parameters[:dq] if rsa_parameters[:dq]
              rsa_key.iqmp = rsa_parameters[:qi] if rsa_parameters[:qi]
            end
          end
        end

        def decode_open_ssl_bn(jwk_data)
          return nil unless jwk_data

          OpenSSL::BN.new(::JWT::Base64.url_decode(jwk_data), BINARY)
        end
      end
    end
  end
end
