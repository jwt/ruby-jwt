# frozen_string_literal: true

module JWT
  module JWK
    class KeyFinder
      def initialize(options)
        jwks_or_loader = options[:jwks]

        @jwks_loader = if jwks_or_loader.respond_to?(:call)
          jwks_or_loader
        else
          ->(_options) { jwks_or_loader }
        end
      end

      def key_for(kid)
        raise ::JWT::DecodeError, 'No key id (kid) found from token headers' unless kid

        jwk = resolve_key(kid)

        raise ::JWT::DecodeError, 'No keys found in jwks' unless @jwks.any?
        raise ::JWT::DecodeError, "Could not find public key for kid #{kid}" unless jwk

        jwk.keypair
      end

      private

      def resolve_key(kid)
        # First try without invalidation to facilitate application caching
        @jwks ||= JWT::JWK::Set.new(@jwks_loader.call(kid: kid))
        jwk = @jwks.find { |key| key[:kid] == kid }

        return jwk if jwk

        # Second try, invalidate for backwards compatibility
        @jwks = JWT::JWK::Set.new(@jwks_loader.call(invalidate: true, kid_not_found: true, kid: kid))
        @jwks.find { |key| key[:kid] == kid }
      end
    end
  end
end
