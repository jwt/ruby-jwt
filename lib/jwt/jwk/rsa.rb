# frozen_string_literal: true

require_relative 'rsa/private_key'
require_relative 'rsa/public_key'

module JWT
  module JWK
    module RSA
      include KeyAlgorithm

      BINARY           = 2
      KTY              = 'RSA'.freeze
      KTYS             = [KTY, OpenSSL::PKey::RSA].freeze
      RSA_KEY_ELEMENTS = %i[n e d p q dp dq qi].freeze

      class << self
        def create(keypair, kid = nil)
          if keypair.is_a?(OpenSSL::PKey::RSA) && keypair.private?
            PrivateKey.new(keypair, kid)
          else
            PublicKey.new(keypair, kid)
          end
        end

        alias new create

        def import(jwk_data)
          pkey_params = jwk_attributes(jwk_data, *RSA_KEY_ELEMENTS) do |value|
            decode_open_ssl_bn(value)
          end
          kid = jwk_attributes(jwk_data, :kid)[:kid]
          create(rsa_pkey(pkey_params), kid)
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

          populate_key(OpenSSL::PKey::RSA.new, rsa_parameters)
        end

        if OpenSSL::PKey::RSA.new.respond_to?(:set_key)
          def populate_key(rsa_key, rsa_parameters)
            rsa_key.set_key(rsa_parameters[:n], rsa_parameters[:e], rsa_parameters[:d])
            rsa_key.set_factors(rsa_parameters[:p], rsa_parameters[:q]) if rsa_parameters[:p] && rsa_parameters[:q]
            rsa_key.set_crt_params(rsa_parameters[:dp], rsa_parameters[:dq], rsa_parameters[:qi]) if rsa_parameters[:dp] && rsa_parameters[:dq] && rsa_parameters[:qi]
            rsa_key
          end
        else
          def populate_key(rsa_key, rsa_parameters)
            rsa_key.n = rsa_parameters[:n]
            rsa_key.e = rsa_parameters[:e]
            rsa_key.d = rsa_parameters[:d] if rsa_parameters[:d]
            rsa_key.p = rsa_parameters[:p] if rsa_parameters[:p]
            rsa_key.q = rsa_parameters[:q] if rsa_parameters[:q]
            rsa_key.dmp1 = rsa_parameters[:dp] if rsa_parameters[:dp]
            rsa_key.dmq1 = rsa_parameters[:dq] if rsa_parameters[:dq]
            rsa_key.iqmp = rsa_parameters[:qi] if rsa_parameters[:qi]

            rsa_key
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
