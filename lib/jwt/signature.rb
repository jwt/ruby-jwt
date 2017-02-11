# frozen_string_literal: true
require 'openssl'

module JWT
  module Signature
    extend self

    NAMED_CURVES = {
      'prime256v1' => 'ES256',
      'secp384r1' => 'ES384',
      'secp521r1' => 'ES512'
    }.freeze

    def sign(algorithm, msg, key)
      if %w(HS256 HS384 HS512).include?(algorithm)
        sign_hmac(algorithm, msg, key)
      elsif %w(RS256 RS384 RS512).include?(algorithm)
        sign_rsa(algorithm, msg, key)
      elsif %w(ES256 ES384 ES512).include?(algorithm)
        sign_ecdsa(algorithm, msg, key)
      else
        raise NotImplementedError, 'Unsupported signing method'
      end
    end

    private

    def sign_rsa(algorithm, msg, private_key)
      raise EncodeError, "The given key is a #{private_key.class}. It has to be an OpenSSL::PKey::RSA instance." if private_key.class == String
      private_key.sign(OpenSSL::Digest.new(algorithm.sub('RS', 'sha')), msg)
    end

    def sign_ecdsa(algorithm, msg, private_key)
      key_algorithm = NAMED_CURVES[private_key.group.curve_name]
      if algorithm != key_algorithm
        raise IncorrectAlgorithm, "payload algorithm is #{algorithm} but #{key_algorithm} signing key was provided"
      end

      digest = OpenSSL::Digest.new(algorithm.sub('ES', 'sha'))
      asn1_to_raw(private_key.dsa_sign_asn1(digest.digest(msg)), private_key)
    end

    def sign_hmac(algorithm, msg, key)
      OpenSSL::HMAC.digest(OpenSSL::Digest.new(algorithm.sub('HS', 'sha')), key, msg)
    end

    def asn1_to_raw(signature, public_key)
      byte_size = (public_key.group.degree + 7) / 8
      OpenSSL::ASN1.decode(signature).value.map { |value| value.value.to_s(2).rjust(byte_size, "\x00") }.join
    end
  end
end
