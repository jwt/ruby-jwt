# frozen_string_literal: true

module JWT
  module Algos
    module Ps
      # RSASSA-PSS signing algorithms

      module_function

      SUPPORTED = %w[PS256 PS384 PS512].freeze

      def sign(algorithm, msg, key)
        require_openssl!

        key_class = key.class

        raise EncodeError, "The given key is a #{key_class}. It has to be an OpenSSL::PKey::RSA instance." if key_class == String

        translated_algorithm = algorithm.sub('PS', 'sha')

        key.sign_pss(translated_algorithm, msg, salt_length: :digest, mgf1_hash: translated_algorithm)
      end

      def verify(algorithm, public_key, signing_input, signature)
        require_openssl!

        SecurityUtils.verify_ps(algorithm, public_key, signing_input, signature)
      end

      def require_openssl!
        if Object.const_defined?('OpenSSL')
          if ::Gem::Version.new(OpenSSL::VERSION) < ::Gem::Version.new('2.1')
            raise JWT::RequiredDependencyError, "You currently have OpenSSL #{OpenSSL::VERSION}. PS support requires >= 2.1"
          end
        else
          raise JWT::RequiredDependencyError, 'PS signing requires OpenSSL +2.1'
        end
      end
    end
  end
end
