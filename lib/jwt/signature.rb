# frozen_string_literal: true

require 'jwt/security_utils'
require 'openssl'
begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

# JWT::Signature module
module JWT
  # Signature logic for JWT
  module Signature
    extend self

    HMAC_ALGORITHMS = %w[HS256 HS512256 HS384 HS512].freeze
    RSA_ALGORITHMS = %w[RS256 RS384 RS512].freeze
    ECDSA_ALGORITHMS = %w[ES256 ES384 ES512].freeze
    EDDSA_ALGORITHMS = %w[ED25519].freeze

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
      elsif EDDSA_ALGORITHMS.include?(algorithm)
        sign_eddsa(algorithm, msg, key)
      else
        raise NotImplementedError, 'Unsupported signing method'
      end
    end

    def verify(algo, key, signing_input, signature)
      verified = if HMAC_ALGORITHMS.include?(algo)
        verify_hmac(algo, key, signing_input, signature)
      elsif RSA_ALGORITHMS.include?(algo)
        SecurityUtils.verify_rsa(algo, key, signing_input, signature)
      elsif ECDSA_ALGORITHMS.include?(algo)
        verify_ecdsa(algo, key, signing_input, signature)
      elsif EDDSA_ALGORITHMS.include?(algo)
        verify_eddsa(algo, key, signing_input, signature)
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
      SecurityUtils.asn1_to_raw(private_key.dsa_sign_asn1(digest.digest(msg)), private_key)
    end

    def sign_eddsa(algorithm, msg, private_key)
      raise EncodeError, "Key given is a #{private_key.class} but has to be an RbNaCl::Signatures::Ed25519::SigningKey" if private_key.class != RbNaCl::Signatures::Ed25519::SigningKey
      raise IncorrectAlgorithm, "payload algorithm is #{algorithm} but #{private_key.primitive} signing key was provided"  if algorithm.downcase.to_sym != private_key.primitive
      private_key.sign(msg)
    end

    def sign_hmac(algorithm, msg, key)
      authenticator, padded_key = SecurityUtils.rbnacl_fixup(algorithm, key)
      if authenticator && padded_key
        authenticator.auth(padded_key, msg.encode('binary'))
      else
        OpenSSL::HMAC.digest(OpenSSL::Digest.new(algorithm.sub('HS', 'sha')), key, msg)
      end
    end

    def verify_eddsa(algorithm, public_key, signing_input, signature)
      raise IncorrectAlgorithm, "payload algorithm is #{algorithm} but #{public_key.primitive} verification key was provided" if algorithm.downcase.to_sym != public_key.primitive
      raise DecodeError, "key given is a #{public_key.class} but has to be a RbNaCl::Signatures::Ed25519::VerifyKey" if public_key.class != RbNaCl::Signatures::Ed25519::VerifyKey
      public_key.verify(signature, signing_input)
    end

    def verify_ecdsa(algorithm, public_key, signing_input, signature)
      key_algorithm = NAMED_CURVES[public_key.group.curve_name]
      if algorithm != key_algorithm
        raise IncorrectAlgorithm, "payload algorithm is #{algorithm} but #{key_algorithm} verification key was provided"
      end
      digest = OpenSSL::Digest.new(algorithm.sub('ES', 'sha'))
      public_key.dsa_verify_asn1(digest.digest(signing_input), SecurityUtils.raw_to_asn1(signature, public_key))
    end

    def verify_hmac(algorithm, public_key, signing_input, signature)
      authenticator, padded_key = SecurityUtils.rbnacl_fixup(algorithm, public_key)
      if authenticator && padded_key
        begin
          authenticator.verify(padded_key, signature.encode('binary'), signing_input.encode('binary'))
        rescue RbNaCl::BadAuthenticatorError
          false
        end
      else
        SecurityUtils.secure_compare(signature, sign_hmac(algorithm, signing_input, public_key))
      end
    end
  end
end
