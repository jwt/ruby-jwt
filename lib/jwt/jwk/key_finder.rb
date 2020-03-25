# frozen_string_literal: true

module JWT
  module JWK
    class KeyFinder
      def initialize(options)
        jwks_or_loader = options[:jwks]
        @jwks          = hash_keys(jwks_or_loader) if jwks_or_loader.is_a?(Hash)
        @jwk_loader    = jwks_or_loader if jwks_or_loader.respond_to?(:call)
      end

      def key_for(kid)
        raise ::JWT::DecodeError, 'No key id (kid) found from token headers' unless kid

        jwk = resolve_key(kid)

        raise ::JWT::DecodeError, 'No keys found in jwks' if jwks_keys.empty?
        raise ::JWT::DecodeError, "Could not find public key for kid #{kid}" unless jwk

        ::JWT::JWK.import(jwk).keypair
      end

      private

      def resolve_key(kid)
        jwk = jwks[kid]
        jwk ||= reload && jwks[kid]
        jwk
      end

      def reload
        load_keys(invalidate: true) if reloadable?
      end

      def jwks
        @jwks || load_keys
      end

      def load_keys(opts = {})
        @jwks = hash_keys(@jwk_loader.call(opts))
      end

      def hash_keys(input)
        kvpairs = Array(input[:keys] || input['keys']).map do |key|
          [key[:kid] || key['kid'], key]
        end
        Hash[kvpairs]
      end

      def reloadable?
        @jwk_loader
      end
    end
  end
end
