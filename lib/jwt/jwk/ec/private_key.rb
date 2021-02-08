# frozen_string_literal: true

require 'forwardable'

module JWT
  module JWK
    module EC
      class PrivateKey
        extend Forwardable
        CAPABILITIES = %i[verify sign].freeze

        def_delegators :public_key, :kid, :verify_key

        def initialize(keypair, kid = nil)
          raise ArgumentError, 'keypair must be of type OpenSSL::PKey::EC' unless keypair.is_a?(OpenSSL::PKey::EC)
          raise ArgumentError, 'keypair needs to contain a private key' unless keypair.private_key?
          @keypair = keypair
          @public_key = PublicKey.new(keypair.public_key, kid)
        end

        def export(options = {})
          exported_key = public_key.export(options)

          if options[:include_private]
            exported_key[:d] = ::JWT::JWK.encode_open_ssl_bn(keypair.private_key.to_bn)
          end

          exported_key
        end

        def signing_key
          keypair
        end

        def encryption_key
          raise ::JWT::JWKError, 'encryption_key is not available'
        end

        def decryption_key
          raise ::JWT::JWKError, 'decryption_key is not available'
        end

        def capabilities
          CAPABILITIES
        end

        private

        attr_reader :public_key, :keypair
      end
    end
  end
end
