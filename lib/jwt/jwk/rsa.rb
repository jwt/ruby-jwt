# frozen_string_literal: true

module JWT
  module JWK
    class RSA < KeyBase
      BINARY = 2
      KTY    = 'RSA'
      KTYS   = [KTY, OpenSSL::PKey::RSA, JWT::JWK::RSA].freeze
      RSA_PUBLIC_KEY_ELEMENTS  = %i[kty n e].freeze
      RSA_PRIVATE_KEY_ELEMENTS = %i[d p q dp dq qi].freeze
      RSA_KEY_ELEMENTS = (RSA_PRIVATE_KEY_ELEMENTS + RSA_PUBLIC_KEY_ELEMENTS).freeze

      def initialize(key, params = nil, options = {})
        params ||= {}

        # For backwards compatibility when kid was a String
        params = { kid: params } if params.is_a?(String)

        key_params = case key
                     when JWT::JWK::RSA
                       key.export(include_private: true)
                     when OpenSSL::PKey::RSA # Accept OpenSSL key as input
                       @keypair = key # Preserve the object to avoid recreation
                       parse_rsa_key(key)
                     when Hash
                       key.transform_keys(&:to_sym)
                     else
                       raise ArgumentError, 'key must be of type OpenSSL::PKey::RSA or Hash with key parameters'
        end

        params = params.transform_keys(&:to_sym)
        check_jwk(key_params, params)

        super(options, key_params.merge(params))
      end

      def keypair
        @keypair ||= create_rsa_key(jwk_attributes(*(RSA_KEY_ELEMENTS - [:kty])))
      end

      def private?
        keypair.private?
      end

      def public_key
        keypair.public_key
      end

      def export(options = {})
        exported = parameters.clone
        exported.reject! { |k, _| RSA_PRIVATE_KEY_ELEMENTS.include? k } unless private? && options[:include_private] == true
        exported
      end

      def members
        RSA_PUBLIC_KEY_ELEMENTS.each_with_object({}) { |i, h| h[i] = self[i] }
      end

      def key_digest
        sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer.new(public_key.n),
                                            OpenSSL::ASN1::Integer.new(public_key.e)])
        OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
      end

      def []=(key, value)
        if RSA_KEY_ELEMENTS.include?(key.to_sym)
          raise ArgumentError, 'cannot overwrite cryptographic key attributes'
        end

        super(key, value)
      end

      private

      def check_jwk(keypair, params)
        raise ArgumentError, 'cannot overwrite cryptographic key attributes' unless (RSA_KEY_ELEMENTS & params.keys).empty?
        raise JWT::JWKError, "Incorrect 'kty' value: #{keypair[:kty]}, expected #{KTY}" unless keypair[:kty] == KTY
        raise JWT::JWKError, 'Key format is invalid for RSA' unless keypair[:n] && keypair[:e]
      end

      def parse_rsa_key(key)
        {
          kty: KTY,
          n: encode_open_ssl_bn(key.n),
          e: encode_open_ssl_bn(key.e),
          d: encode_open_ssl_bn(key.d),
          p: encode_open_ssl_bn(key.p),
          q: encode_open_ssl_bn(key.q),
          dp: encode_open_ssl_bn(key.dmp1),
          dq: encode_open_ssl_bn(key.dmq1),
          qi: encode_open_ssl_bn(key.iqmp)
        }.compact
      end

      def jwk_attributes(*attributes)
        attributes.each_with_object({}) do |attribute, hash|
          hash[attribute] = decode_open_ssl_bn(self[attribute])
        end
      end

      def encode_open_ssl_bn(key_part)
        return unless key_part

        ::JWT::Base64.url_encode(key_part.to_s(BINARY))
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

      class << self
        def import(jwk_data)
          new(jwk_data)
        end
      end
    end
  end
end
