# frozen_string_literal: true

module JWT
  module Algos
    module Hmac
      module_function

      SUPPORTED = %w[HS256 HS512256 HS384 HS512].freeze

      def sign(algorithm, msg, key)
        key ||= ''
        authenticator, padded_key = SecurityUtils.rbnacl_fixup(algorithm, key)
        if authenticator && padded_key
          authenticator.auth(padded_key, msg.encode('binary'))
        else
          OpenSSL::HMAC.digest(OpenSSL::Digest.new(algorithm.sub('HS', 'sha')), key, msg)
        end
      end

      def verify(algorithm, public_key, signing_input, signature)
        authenticator, padded_key = SecurityUtils.rbnacl_fixup(algorithm, public_key)
        if authenticator && padded_key
          begin
            authenticator.verify(padded_key, signature.encode('binary'), signing_input.encode('binary'))
          rescue RbNaCl::BadAuthenticatorError
            false
          end
        else
          SecurityUtils.secure_compare(signature, sign(algorithm, signing_input, public_key))
        end
      end
    end
  end
end
