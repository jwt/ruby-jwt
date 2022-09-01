# frozen_string_literal: true

module JWT
  module Algos
    module Ecdsa
      module_function

      NAMED_CURVES = {
        'prime256v1' => {
          algorithm: 'ES256',
          digest: 'sha256'
        },
        'secp256r1' => { # alias for prime256v1
          algorithm: 'ES256',
          digest: 'sha256'
        },
        'secp384r1' => {
          algorithm: 'ES384',
          digest: 'sha384'
        },
        'secp521r1' => {
          algorithm: 'ES512',
          digest: 'sha512'
        },
        'secp256k1' => {
          algorithm: 'ES256K',
          digest: 'sha256'
        }
      }.freeze

      SUPPORTED = NAMED_CURVES.map { |_, c| c[:algorithm] }.uniq.freeze

      def sign(algorithm, msg, key)
        curve_definition = curve_by_name(key.group.curve_name)
        key_algorithm = curve_definition[:algorithm]
        if algorithm != key_algorithm
          raise IncorrectAlgorithm, "payload algorithm is #{algorithm} but #{key_algorithm} signing key was provided"
        end

        digest = OpenSSL::Digest.new(curve_definition[:digest])
        SecurityUtils.asn1_to_raw(key.dsa_sign_asn1(digest.digest(msg)), key)
      end

      def verify(algorithm, public_key, signing_input, signature)
        curve_definition = curve_by_name(public_key.group.curve_name)
        key_algorithm = curve_definition[:algorithm]
        if algorithm != key_algorithm
          raise IncorrectAlgorithm, "payload algorithm is #{algorithm} but #{key_algorithm} verification key was provided"
        end

        digest = OpenSSL::Digest.new(curve_definition[:digest])
        public_key.dsa_verify_asn1(digest.digest(signing_input), SecurityUtils.raw_to_asn1(signature, public_key))
      end

      def curve_by_name(name)
        NAMED_CURVES.fetch(name) do
          raise UnsupportedEcdsaCurve, "The ECDSA curve '#{name}' is not supported"
        end
      end
    end
  end
end
