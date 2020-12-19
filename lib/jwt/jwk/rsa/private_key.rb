# frozen_string_literal: true

require 'forwardable'

module JWT
  module JWK
    module RSA
      class PrivateKey
        extend Forwardable

        CAPABILITIES = %i[verify sign encrypt decrypt].freeze

        def_delegators :public_key, :kid

        def initialize(keypair, kid = nil)
          raise ArgumentError, 'keypair must be of type OpenSSL::PKey::RSA' unless keypair.is_a?(OpenSSL::PKey::RSA)
          raise ArgumentError, 'keypair needs to contain a private keypair' unless keypair.private?
          @keypair = keypair
          @public_key = PublicKey.new(keypair.public_key, kid)
        end

        def keypair
          warn('Deprecated: The #keypair method for JWK classes is deprecated. ' \
               'Use the use-case specific #verify_key or #signing_key methods')
          @keypair
        end

        def private?
          warn('Deprecated: The #private? method for JWK classes is deprecated. ' \
               'To get key capabilities use the #capabilites method')
          true
        end

        def export(options = {})
          exported_key = public_key.export(options)

          if options[:include_private]
            append_private_parts(exported_key)
          end

          exported_key
        end

        def capabilities
          CAPABILITIES
        end

        def signing_key
          @keypair
        end

        alias encryption_key signing_key

        def verify_key
          public_key.verify_key
        end

        alias decryption_key verify_key

        private

        def append_private_parts(exported_public_key)
          exported_public_key.merge!(
            d: ::JWT::JWK.encode_open_ssl_bn(signing_key.d),
            p: ::JWT::JWK.encode_open_ssl_bn(signing_key.p),
            q: ::JWT::JWK.encode_open_ssl_bn(signing_key.q),
            dp: ::JWT::JWK.encode_open_ssl_bn(signing_key.dmp1),
            dq: ::JWT::JWK.encode_open_ssl_bn(signing_key.dmq1),
            qi: ::JWT::JWK.encode_open_ssl_bn(signing_key.iqmp)
          )
        end

        attr_reader :public_key
      end
    end
  end
end
