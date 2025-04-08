# frozen_string_literal: true

module JWT
  module JWK
    # JSON Web Key keyfinder
    # To find the key for a given kid
    class KeyFinder
      # Initializes a new KeyFinder instance.
      # @param [Hash] options the options to create a KeyFinder with
      # @option options [Proc, JWT::JWK::Set] :jwks the jwks or a loader proc
      # @option options [Boolean] :allow_nil_kid whether to allow nil kid
      def initialize(options)
        @allow_nil_kid = options[:allow_nil_kid]
        jwks_or_loader = options[:jwks]

        @jwks_loader = if jwks_or_loader.respond_to?(:call)
                         jwks_or_loader
                       else
                         ->(_options) { jwks_or_loader }
                       end
      end

      # Returns the verification key for the given kid
      # @param [String] kid the key id
      def key_for(kid, key_field = :kid)
        raise ::JWT::DecodeError, "Invalid type for #{key_field} header parameter" unless kid.nil? || kid.is_a?(String)

        jwk = resolve_key(kid, key_field)

        raise ::JWT::DecodeError, 'No keys found in jwks' unless @jwks.any?
        raise ::JWT::DecodeError, "Could not find public key for kid #{kid}" unless jwk

        jwk.verify_key
      end

      # Returns the key for the given token
      # @param [JWT::EncodedToken] token the token
      def call(token)
        kid = token.header['kid']
        x5t = token.header['x5t']
        x5c = token.header['x5c']

        if kid
          key_for(kid, :kid)
        elsif x5t
          key_for(x5t, :x5t)
        elsif x5c
          key_for(x5c, :x5c)
        elsif @allow_nil_kid
          key_for(kid)
        else
          raise ::JWT::DecodeError, 'No key id (kid) or x5t found from token headers'
        end
      end

      private

      def resolve_key(kid, key_field)
        key_matcher = ->(key) { (kid.nil? && @allow_nil_kid) || key[key_field] == kid }

        # First try without invalidation to facilitate application caching
        @jwks ||= JWT::JWK::Set.new(@jwks_loader.call(key_field => kid))
        jwk = @jwks.find { |key| key_matcher.call(key) }

        return jwk if jwk

        # Second try, invalidate for backwards compatibility
        @jwks = JWT::JWK::Set.new(@jwks_loader.call(invalidate: true, kid_not_found: true, key_field => kid))
        @jwks.find { |key| key_matcher.call(key) }
      end
    end
  end
end
