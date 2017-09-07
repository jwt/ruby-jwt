# frozen_string_literal: true

require 'jwt/security_utils'
require 'openssl'
require 'jwt/algos/hmac'
require 'jwt/algos/eddsa'
require 'jwt/algos/ecdsa'
require 'jwt/algos/rsa'
begin
  require 'rbnacl'
rescue LoadError => e
  abort(e.message) if defined?(RbNaCl)
end

# JWT::Signature module
module JWT
  # Signature logic for JWT
  module Signature
    extend self
    ALGOS = [
      Algos::Hmac,
      Algos::Ecdsa,
      Algos::Rsa,
      Algos::Eddsa
    ]
    ToSign = Struct.new(:algorithm, :msg, :key)
    ToVerify = Struct.new(:algorithm, :public_key, :signing_input, :signature)

    def sign(algorithm, msg, key)
      algo = ALGOS.find{|algo|
        algo.const_get(:SUPPORTED).include? algorithm 
      } 
      raise NotImplementedError, 'Unsupported signing method' if algo.nil? 
      algo.sign ToSign.new(algorithm, msg, key) 
    end

    def verify(algorithm, key, signing_input, signature)
      algo = ALGOS.find{|algo|
        algo.const_get(:SUPPORTED).include? algorithm 
      }

      raise JWT::VerificationError, 'Algorithm not supported' if algo.nil?
      verified = algo.verify(ToVerify.new(algorithm, key, signing_input, signature)) 
      raise(JWT::VerificationError, 'Signature verification raised') unless verified
    rescue OpenSSL::PKey::PKeyError
      raise JWT::VerificationError, 'Signature verification raised'
    ensure
      OpenSSL.errors.clear
    end
  end
end
