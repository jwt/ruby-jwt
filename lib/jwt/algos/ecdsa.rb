# frozen_string_literal: true

module JWT
  module Algos
    module Ecdsa
      module_function

      NAMED_CURVES = {
        'prime256v1' => 'ES256',
        'secp256r1' => 'ES256', # alias for prime256v1
        'secp384r1' => 'ES384',
        'secp521r1' => 'ES512'
      }.freeze

      SUPPORTED = NAMED_CURVES.values.uniq.freeze

      def sign(to_sign)
        algorithm, msg, key = to_sign.values
        curve_definition = curve_by_name(key.group.curve_name)
        key_algorithm = curve_definition[:algorithm]
        if algorithm != key_algorithm
          raise IncorrectAlgorithm, "payload algorithm is #{algorithm} but #{key_algorithm} signing key was provided"
        end

        digest = OpenSSL::Digest.new(curve_definition[:digest])
        SecurityUtils.asn1_to_raw(key.dsa_sign_asn1(digest.digest(msg)), key)
      end

      def verify(to_verify)
        algorithm, public_key, signing_input, signature = to_verify.values
        curve_definition = curve_by_name(public_key.group.curve_name)
        key_algorithm = curve_definition[:algorithm]
        if algorithm != key_algorithm
          raise IncorrectAlgorithm, "payload algorithm is #{algorithm} but #{key_algorithm} verification key was provided"
        end

        digest = OpenSSL::Digest.new(curve_definition[:digest])
        public_key.dsa_verify_asn1(digest.digest(signing_input), SecurityUtils.raw_to_asn1(signature, public_key))
      end

      def curve_by_name(name)
        algorithm = NAMED_CURVES.fetch(name) do
          raise UnsupportedEcdsaCurve, "The ECDSA curve '#{name}' is not supported"
        end

        {
          algorithm: algorithm,
          digest: algorithm.sub('ES', 'sha')
        }
      end
    end
  end
end
