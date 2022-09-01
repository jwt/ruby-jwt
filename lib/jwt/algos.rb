# frozen_string_literal: true

begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end
require 'openssl'

require 'jwt/security_utils'
require 'jwt/algos/hmac'
require 'jwt/algos/eddsa'
require 'jwt/algos/ecdsa'
require 'jwt/algos/rsa'
require 'jwt/algos/ps'
require 'jwt/algos/none'
require 'jwt/algos/unsupported'
require 'jwt/algos/algo_wrapper'

module JWT
  module Algos
    extend self

    ALGOS = [
      Algos::Hmac,
      Algos::Ecdsa,
      Algos::Rsa,
      Algos::Eddsa,
      Algos::Ps,
      Algos::None,
      Algos::Unsupported
    ].freeze

    def find(algorithm)
      indexed[algorithm && algorithm.downcase]
    end

    def create(algorithm)
      cls, alg = find(algorithm)
      Algos::AlgoWrapper.new(alg, cls)
    end

    private

    def indexed
      @indexed ||= begin
        fallback = [Algos::Unsupported, nil]
        ALGOS.each_with_object(Hash.new(fallback)) do |cls, hash|
          cls.const_get(:SUPPORTED).each do |alg|
            hash[alg.downcase] = [cls, alg]
          end
        end
      end
    end
  end
end
