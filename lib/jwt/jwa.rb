# frozen_string_literal: true

require 'openssl'

begin
  require 'rbnacl'
rescue LoadError
  raise if defined?(RbNaCl)
end

require_relative 'jwa/wrappers/external_agorithm'
require_relative 'jwa/wrappers/registered_algorithm'
require_relative 'jwa/signature_algorithm'
require_relative 'jwa/hmac'
require_relative 'jwa/eddsa'
require_relative 'jwa/ecdsa'
require_relative 'jwa/rsa'
require_relative 'jwa/ps'
require_relative 'jwa/none'

if JWT.rbnacl_6_or_greater?
  require_relative 'jwa/hmac_rbnacl'
elsif JWT.rbnacl?
  require_relative 'jwa/hmac_rbnacl_fixed'
end

module JWT
  module JWA
    class << self
      def resolve(algorithm)
        return find(algorithm) if algorithm.is_a?(String) || algorithm.is_a?(Symbol)

        Wrappers::ExternalAlgorithm.new(algorithm)
      end
    end
  end
end
