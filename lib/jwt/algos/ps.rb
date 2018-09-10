module JWT
  module Algos
    module Ps
      module_function

      SUPPORTED = %w[PS256 PS384 PS512].freeze

      def sign(to_sign)
        algorithm, msg, key = to_sign.values

        key_class = key.class

        raise EncodeError, "The given key is a #{key_class}. It has to be an OpenSSL::PKey::RSA instance." if key_class == String

        translated_algorithm = algorithm.sub('PS', 'sha')

        key.sign_pss(translated_algorithm, msg, salt_length: :max, mgf1_hash: translated_algorithm)
      end

      def verify(to_verify)
        SecurityUtils.verify_ps(to_verify.algorithm, to_verify.public_key, to_verify.signing_input, to_verify.signature)
      end
    end
  end
end
