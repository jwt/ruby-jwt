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
      def key_for(kid)
        raise ::JWT::DecodeError, 'No key id (kid) found from token headers' unless kid || @allow_nil_kid
        raise ::JWT::DecodeError, 'Invalid type for kid header parameter' unless kid.nil? || kid.is_a?(String)

        jwk = resolve_key(kid)

        raise ::JWT::DecodeError, 'No keys found in jwks' unless @jwks.any?
        raise ::JWT::DecodeError, "Could not find public key for kid #{kid}" unless jwk

        jwk.verify_key
      end

      # Returns the key for the given token
      # @param [JWT::EncodedToken] token the token
      def call(token)
        key_for(token.header['kid'])
      end

      private

      def resolve_key(kid)
        key_matcher = ->(key) { (kid.nil? && @allow_nil_kid) || key[:kid] == kid }

        # First try without invalidation to facilitate application caching
        @jwks ||= JWT::JWK::Set.new(@jwks_loader.call(kid: kid))
        jwk = @jwks.find { |key| key_matcher.call(key) }

        return jwk if jwk

        # Second try, invalidate for backwards compatibility
        @jwks = JWT::JWK::Set.new(@jwks_loader.call(invalidate: true, kid_not_found: true, kid: kid))
        @jwks.find { |key| key_matcher.call(key) }
      end
    end
  end
end
