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
      # @option options [Array] :key_fields the fields to use for key matching,
      #                         the order of the fields are used to determine
      #                         the priority of the keys.
      def initialize(options)
        @allow_nil_kid = options[:allow_nil_kid]
        jwks_or_loader = options[:jwks]

        @jwks_loader = if jwks_or_loader.respond_to?(:call)
                         jwks_or_loader
                       else
                         ->(_options) { jwks_or_loader }
                       end

        @key_fields = options[:key_fields] || %i[kid]
      end

      # Returns the verification key for the given kid
      # @param [String] kid the key id
      # @param [Symbol] key_field the JWK field to match
      def key_for(kid, key_field = :kid)
        find_jwk(kid, key_field).verify_key
      end

      # Returns the key for the given token
      # @param [JWT::EncodedToken] token the token
      # @return [JWT::JWK::KeyBase, Object] the JWK when alg is present, otherwise its raw verification key
      def call(token)
        key_field = @key_fields.find { |field| token.header[field.to_s] }

        raise ::JWT::SignatureError, 'No key id (kid) or x5t found from token headers' unless key_field || @allow_nil_kid

        key_field ||= :kid
        jwk = find_jwk(token.header[key_field.to_s], key_field, token.header['alg'])
        jwk.parameters.key?(:alg) ? jwk : jwk.verify_key
      end

      private

      def find_jwk(kid, key_field, algorithm = nil)
        raise ::JWT::MalformedTokenError, "Invalid type for #{key_field} header parameter" unless kid.nil? || kid.is_a?(String)

        jwk = resolve_key(kid, key_field, algorithm)

        raise ::JWT::SignatureError, 'No keys found in jwks' unless @jwks.any?
        raise ::JWT::SignatureError, "Could not find public key for kid #{kid}" unless jwk

        jwk
      end

      def resolve_key(kid, key_field, algorithm)
        # First try without invalidation to facilitate application caching
        @jwks ||= JWT::JWK::Set.new(@jwks_loader.call(key_field => kid))
        jwk = matching_key(kid, key_field, algorithm)

        return jwk if jwk

        # Second try, invalidate for backwards compatibility
        @jwks = JWT::JWK::Set.new(@jwks_loader.call(invalidate: true, kid_not_found: true, key_field => kid))
        matching_key(kid, key_field, algorithm)
      end

      def matching_key(kid, key_field, algorithm)
        @jwks.find do |key|
          ((kid.nil? && @allow_nil_kid) || key[key_field] == kid) && key.usable_for_verification?(algorithm)
        end
      end
    end
  end
end
