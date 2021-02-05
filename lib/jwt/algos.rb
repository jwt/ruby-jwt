# frozen_string_literal: true

require 'jwt/algos/hmac'
require 'jwt/algos/eddsa'
require 'jwt/algos/ecdsa'
require 'jwt/algos/rsa'
require 'jwt/algos/ps'
require 'jwt/algos/unsupported'

# JWT::Signature module
module JWT
  # Signature logic for JWT
  module Algos
    extend self
    ALGOS = [
      Algos::Hmac,
      Algos::Ecdsa,
      Algos::Rsa,
      Algos::Eddsa,
      Algos::Ps,
      Algos::Unsupported
    ].freeze

    def find(algorithm)
      ALGOS.each do |alg|
        code = alg.const_get(:SUPPORTED).find {|a| a.upcase == algorithm.upcase }
        return [alg, code] if code
      end
      nil
    end
  end
end
