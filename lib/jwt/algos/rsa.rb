# frozen_string_literal: true

module JWT
  module Algos
    module Rsa
      module_function

      SUPPORTED = %w[RS256 RS384 RS512].freeze

      def sign(algorithm, msg, key)
        raise EncodeError, "The given key is a #{key.class}. It has to be an OpenSSL::PKey::RSA instance." if key.instance_of?(String)

        key.sign(OpenSSL::Digest.new(algorithm.sub('RS', 'sha')), msg)
      end

      def verify(algorithm, public_key, signing_input, signature)
        SecurityUtils.verify_rsa(algorithm, public_key, signing_input, signature)
      end
    end
  end
end
