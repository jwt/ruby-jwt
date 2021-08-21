module JWT
  module Algos
    module Hmac
      module_function

      SUPPORTED = %w[HS256 HS512256 HS384 HS512].freeze

      def sign(to_sign)
        algorithm, msg, key = to_sign.values
        key ||= ''
        authenticator, padded_key = rbnacl_fixup(algorithm, key)
        if authenticator && padded_key
          authenticator.auth(padded_key, msg.encode('binary'))
        else
          OpenSSL::HMAC.digest(OpenSSL::Digest.new(algorithm.sub('HS', 'sha')), key, msg)
        end
      end

      def verify(to_verify)
        algorithm, public_key, signing_input, signature = to_verify.values
        authenticator, padded_key = rbnacl_fixup(algorithm, public_key)
        if authenticator && padded_key
          begin
            authenticator.verify(padded_key, signature.encode('binary'), signing_input.encode('binary'))
          rescue RbNaCl::BadAuthenticatorError
            false
          end
        else
          SecurityUtils.secure_compare(signature, sign(JWT::Signature::ToSign.new(algorithm, signing_input, public_key)))
        end
      end

      def rbnacl_fixup(algorithm, key)
        algorithm = algorithm.sub('HS', 'SHA').to_sym

        return [] unless defined?(RbNaCl) && RbNaCl::HMAC.constants(false).include?(algorithm)

        authenticator = RbNaCl::HMAC.const_get(algorithm)

        # Fall back to OpenSSL for keys larger than 32 bytes.
        return [] if key.bytesize > authenticator.key_bytes

        [
          authenticator,
          key.bytes.fill(0, key.bytesize...authenticator.key_bytes).pack('C*')
        ]
      end
    end
  end
end
