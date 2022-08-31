# frozen_string_literal: true

require 'jwt/security_utils'
require 'openssl'
require 'jwt/algos'
begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

# JWT::Signature module
module JWT
  # Signature logic for JWT
  module Signature
    module_function

    ToVerify = Struct.new(:algorithm, :public_key, :signing_input, :signature)

    def verify(algorithm, key, signing_input, signature)
      algo, code = Algos.find(algorithm)
      algo.verify(ToVerify.new(code, key, signing_input, signature))
    rescue OpenSSL::PKey::PKeyError
      raise JWT::VerificationError, 'Signature verification raised'
    ensure
      OpenSSL.errors.clear
    end
  end
end
