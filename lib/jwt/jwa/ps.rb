# frozen_string_literal: true

module JWT
  module JWA
    # Implementation of the RSASSA-PSS family of algorithms
    class Ps
      include JWT::JWA::SigningAlgorithm

      def initialize(alg)
        @alg = alg
        @digest_algorithm = alg.sub('PS', 'sha')
      end

      def sign(data:, signing_key:)
        raise_sign_error!("The given key is a #{signing_key.class}. It has to be an OpenSSL::PKey::RSA instance.") unless signing_key.is_a?(::OpenSSL::PKey::RSA)
        raise_sign_error!('The key length must be greater than or equal to 2048 bits') if signing_key.n.num_bits < 2048

        signing_key.sign_pss(digest_algorithm, data, salt_length: :digest, mgf1_hash: digest_algorithm)
      end

      def verify(data:, signature:, verification_key:)
        verification_key.verify_pss(digest_algorithm, signature, data, salt_length: :auto, mgf1_hash: digest_algorithm)
      rescue OpenSSL::PKey::PKeyError
        raise JWT::VerificationError, 'Signature verification raised'
      end

      register_algorithm(new('PS256'))
      register_algorithm(new('PS384'))
      register_algorithm(new('PS512'))

      private

      attr_reader :digest_algorithm
    end
  end
end
