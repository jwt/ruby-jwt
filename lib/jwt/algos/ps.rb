module JWT
  module Algos
    module Ps
      module_function

      SUPPORTED = %w[PS256 PS384 PS512].freeze

      def sign(to_sign)
        algorithm, msg, key = to_sign.values
        raise EncodeError, "The given key is a #{key.class}. It has to be an OpenSSL::PKey::RSA instance." if key.class == String

        key.sign_pss(algorithm.sub('PS', 'sha'), msg, salt_length: :max, mgf1_hash: algorithm.sub('PS', 'sha'))
      end

      def verify(to_verify)
        SecurityUtils.verify_ps(to_verify.algorithm, to_verify.public_key, to_verify.signing_input, to_verify.signature)
      end
    end
  end
end
