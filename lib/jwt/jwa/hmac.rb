# frozen_string_literal: true

module JWT
  module JWA
    # Implementation of the HMAC family of algorithms
    class Hmac
      include JWT::JWA::SigningAlgorithm

      # Minimum key lengths for HMAC algorithms based on RFC 7518 Section 3.2.
      # Keys must be at least the size of the hash output to ensure sufficient
      # entropy for the algorithm's security level.
      MIN_KEY_LENGTHS = {
        'HS256' => 32,
        'HS384' => 48,
        'HS512' => 64
      }.freeze

      def initialize(alg, digest)
        @alg = alg
        @digest = digest
      end

      def sign(data:, signing_key:)
        validate_key!(signing_key) { |message| raise_sign_error!(message) }

        OpenSSL::HMAC.digest(digest.new, signing_key, data)
      end

      def verify(data:, signature:, verification_key:)
        validate_key!(verification_key) { |message| raise_verify_error!(message) }

        SecurityUtils.secure_compare(signature, OpenSSL::HMAC.digest(digest.new, verification_key, data))
      end

      register_algorithm(new('HS256', OpenSSL::Digest::SHA256))
      register_algorithm(new('HS384', OpenSSL::Digest::SHA384))
      register_algorithm(new('HS512', OpenSSL::Digest::SHA512))

      private

      attr_reader :digest

      # Yields a message for the first problem found with the key. The caller
      # raises it, so signing and verification failures keep their own error class.
      def validate_key!(key)
        yield 'HMAC key expected to be a String' unless key.is_a?(String)
        yield 'HMAC key cannot be empty' if key.empty?

        return unless JWT.configuration.decode.enforce_hmac_key_length

        min_length = MIN_KEY_LENGTHS[alg]
        yield "HMAC key must be at least #{min_length} bytes for #{alg} algorithm" if key.bytesize < min_length
      end

      # Copy of https://github.com/rails/rails/blob/v7.0.3.1/activesupport/lib/active_support/security_utils.rb
      # rubocop:disable-next Naming/MethodParameterName, Style/StringLiterals, Style/NumericPredicate
      module SecurityUtils
        # Constant time string comparison, for fixed length strings.
        #
        # The values compared should be of fixed length, such as strings
        # that have already been processed by HMAC. Raises in case of length mismatch.

        if defined?(OpenSSL.fixed_length_secure_compare)
          def fixed_length_secure_compare(a, b)
            OpenSSL.fixed_length_secure_compare(a, b)
          end
        else
          # :nocov:
          def fixed_length_secure_compare(a, b)
            raise ArgumentError, "string length mismatch." unless a.bytesize == b.bytesize

            l = a.unpack "C#{a.bytesize}"

            res = 0
            b.each_byte { |byte| res |= byte ^ l.shift }
            res == 0
          end
          # :nocov:
        end
        module_function :fixed_length_secure_compare

        # Secure string comparison for strings of variable length.
        #
        # While a timing attack would not be able to discern the content of
        # a secret compared via secure_compare, it is possible to determine
        # the secret length. This should be considered when using secure_compare
        # to compare weak, short secrets to user input.
        def secure_compare(a, b)
          a.bytesize == b.bytesize && fixed_length_secure_compare(a, b)
        end
        module_function :secure_compare
      end
    end
  end
end
