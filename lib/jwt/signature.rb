# frozen_string_literal: true
require 'openssl'

module JWT
  module Signature
    extend self

    HMAC_ALGORITHMS = %w(HS256 HS384 HS512).freeze
    RSA_ALGORITHMS = %w(RS256 RS384 RS512).freeze
    ECDSA_ALGORITHMS = %w(ES256 ES384 ES512).freeze

    NAMED_CURVES = {
      'prime256v1' => 'ES256',
      'secp384r1' => 'ES384',
      'secp521r1' => 'ES512'
    }.freeze

    def sign(algorithm, msg, key)
      if HMAC_ALGORITHMS.include?(algorithm)
        sign_hmac(algorithm, msg, key)
      elsif RSA_ALGORITHMS.include?(algorithm)
        sign_rsa(algorithm, msg, key)
      elsif ECDSA_ALGORITHMS.include?(algorithm)
        sign_ecdsa(algorithm, msg, key)
      else
        raise NotImplementedError, 'Unsupported signing method'
      end
    end

    def verify(algo, key, signing_input, signature)
      verified = if HMAC_ALGORITHMS.include?(algo)
                   secure_compare(signature, sign_hmac(algo, signing_input, key))
                 elsif RSA_ALGORITHMS.include?(algo)
                   verify_rsa(algo, key, signing_input, signature)
                 elsif ECDSA_ALGORITHMS.include?(algo)
                   verify_ecdsa(algo, key, signing_input, signature)
                 else
                   raise JWT::VerificationError, 'Algorithm not supported'
                 end

      raise(JWT::VerificationError, 'Signature verification raised') unless verified
    rescue OpenSSL::PKey::PKeyError
      raise JWT::VerificationError, 'Signature verification raised'
    ensure
      OpenSSL.errors.clear
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

    def verify_rsa(algorithm, public_key, signing_input, signature)
      public_key.verify(OpenSSL::Digest.new(algorithm.sub('RS', 'sha')), signature, signing_input)
    end

    def verify_ecdsa(algorithm, public_key, signing_input, signature)
      key_algorithm = Signature::NAMED_CURVES[public_key.group.curve_name]
      if algorithm != key_algorithm
        raise IncorrectAlgorithm, "payload algorithm is #{algorithm} but #{key_algorithm} verification key was provided"
      end

      digest = OpenSSL::Digest.new(algorithm.sub('ES', 'sha'))
      public_key.dsa_verify_asn1(digest.digest(signing_input), raw_to_asn1(signature, public_key))
    end

    def asn1_to_raw(signature, public_key)
      byte_size = (public_key.group.degree + 7) / 8
      OpenSSL::ASN1.decode(signature).value.map { |value| value.value.to_s(2).rjust(byte_size, "\x00") }.join
    end

    def raw_to_asn1(signature, private_key)
      byte_size = (private_key.group.degree + 7) / 8
      r = signature[0..(byte_size - 1)]
      s = signature[byte_size..-1] || ''
      OpenSSL::ASN1::Sequence.new([r, s].map { |int| OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(int, 2)) }).to_der
    end

    # From devise
    # constant-time comparison algorithm to prevent timing attacks
    def secure_compare(a, b)
      return false if a.nil? || b.nil? || a.empty? || b.empty? || a.bytesize != b.bytesize
      l = a.unpack "C#{a.bytesize}"
      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      res.zero?
    end
  end
end
