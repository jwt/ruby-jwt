# frozen_string_literal: true

module JWT
  module Algos
    module Rsa
      ALGORITHMS_AND_DIGESTS = {
        'RS256' => OpenSSL::Digest::SHA256,
        'RS384' => OpenSSL::Digest::SHA384,
        'RS512' => OpenSSL::Digest::SHA512
      }.freeze

      SUPPORTED = ALGORITHMS_AND_DIGESTS.keys.freeze

      class << self
        def sign(to_sign)
          algorithm, msg, key = to_sign.values

          raise EncodeError, "The given key is a #{key.class}. It has to be an OpenSSL::PKey::RSA instance." unless key.is_a?(OpenSSL::PKey::RSA)

          key.sign(digest_for(algorithm), msg)
        end

        def verify(to_verify)
          verification_key = to_verify.public_key

          raise VerificationError, "The given key is a #{verification_key.class}. It has to be an OpenSSL::PKey::RSA instance." unless verification_key.is_a?(OpenSSL::PKey::RSA)

          verification_key.verify(digest_for(to_verify.algorithm), to_verify.signature, to_verify.signing_input)
        end

        private

        def digest_for(algorithm)
          ALGORITHMS_AND_DIGESTS[algorithm].new
        end
      end
    end
  end
end
