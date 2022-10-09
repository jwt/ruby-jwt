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
      Algos::AlgoWrapper.new(*find(algorithm))
    end

    def implementation?(algorithm)
      algorithm.respond_to?(:valid_alg?) &&
        (algorithm.respond_to?(:sign) || algorithm.respond_to?(:verify))
    end

    private

    def indexed
      @indexed ||= begin
        fallback = [nil, Algos::Unsupported]
        ALGOS.each_with_object(Hash.new(fallback)) do |cls, hash|
          cls.const_get(:SUPPORTED).each do |alg|
            hash[alg.downcase] = [alg, cls]
          end
        end
      end
    end
  end
end
