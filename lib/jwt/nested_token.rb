# frozen_string_literal: true

module JWT
  # Represents a Nested JWT as defined in RFC 7519 Section 5.2, Section 7.1 Step 5, and Appendix A.2.
  #
  # A Nested JWT wraps an existing JWT string as the payload of another signed JWT.
  #
  # @example Creating a Nested JWT
  #   inner_jwt = JWT.encode({ user_id: 123 }, 'inner_secret', 'HS256')
  #   nested = JWT::NestedToken.new(inner_jwt)
  #   nested.sign!(algorithm: 'RS256', key: rsa_private_key)
  #   nested.jwt
  #
  # @example Verifying a Nested JWT
  #   nested = JWT::NestedToken.new(nested_jwt)
  #   tokens = nested.verify!(
  #     keys: [
  #       { algorithm: 'RS256', key: rsa_public_key },
  #       { algorithm: 'HS256', key: 'inner_secret' }
  #     ]
  #   )
  #   tokens.last.payload
  #
  # @see https://datatracker.ietf.org/doc/html/rfc7519#section-5.2 RFC 7519 Section 5.2
  class NestedToken
    CTY_JWT = 'JWT'
    MAX_DEPTH = 10

    # @return [String] the current JWT string represented by this instance.
    attr_reader :jwt

    # @return [Array<JWT::EncodedToken>, nil] verified tokens ordered from outermost to innermost.
    attr_reader :tokens

    # @param jwt [String] the JWT string to wrap or verify.
    # @raise [ArgumentError] if the provided JWT is not a String.
    def initialize(jwt)
      raise ArgumentError, 'Provided JWT must be a String' unless jwt.is_a?(String)

      @jwt = jwt
    end

    # Wraps the current JWT string in an outer JWS and replaces {#jwt} with the nested JWT.
    # The payload is base64url-encoded directly from the JWT string (without JSON string encoding).
    #
    # @param algorithm [String, Object] the algorithm to use for signing.
    # @param key [String, JWT::JWK::KeyBase] the key to use for signing.
    # @param header [Hash] additional header fields to include in the outer token.
    # @return [nil]
    def sign!(algorithm:, key:, header: {})
      signer = JWA.create_signer(algorithm: algorithm, key: key)
      outer_header = (header || {})
                     .transform_keys(&:to_s)
                     .merge('cty' => CTY_JWT)

      outer_header.merge!(signer.jwa.header) { |_header_key, old, _new| old }

      encoded_header = ::JWT::Base64.url_encode(JWT::JSON.generate(outer_header))
      encoded_payload = ::JWT::Base64.url_encode(jwt)
      signing_input = [encoded_header, encoded_payload].join('.')
      signature = signer.sign(data: signing_input)

      @jwt = [encoded_header, encoded_payload, ::JWT::Base64.url_encode(signature)].join('.')
      @tokens = nil
      nil
    end

    # Verifies signatures of all nested levels and the claims of the innermost token.
    #
    # @param keys [Array<Hash>] key configuration per nesting level (outermost to innermost).
    # @param claims [Array<Symbol>, Hash, nil] claim verification options for the innermost token.
    # @return [Array<JWT::EncodedToken>] verified tokens from outermost to innermost.
    def verify!(keys:, claims: nil)
      verify_signatures!(keys: keys)
      verify_claims!(claims: claims)
      tokens
    end

    # Verifies signatures of all nested levels.
    #
    # @param keys [Array<Hash>] key configuration per nesting level (outermost to innermost).
    # @return [Array<JWT::EncodedToken>] verified tokens from outermost to innermost.
    def verify_signatures!(keys:)
      @tokens = EncodedToken.new(jwt).unwrap_all(max_depth: MAX_DEPTH)
      validate_key_count!(keys)

      tokens.each_with_index do |token, index|
        key_config = keys[index]
        token.verify_signature!(
          algorithm: key_config[:algorithm],
          key: key_config[:key],
          key_finder: key_config[:key_finder]
        )
      end

      tokens
    end

    # Verifies claims of the innermost token after signatures have been verified.
    #
    # @param claims [Array<Symbol>, Hash, nil] claim verification options for the innermost token.
    # @return [Array<JWT::EncodedToken>] verified tokens from outermost to innermost.
    def verify_claims!(claims: nil)
      raise JWT::DecodeError, 'Verify nested token signatures before verifying claims' unless tokens

      innermost_token = tokens.last
      claims.is_a?(Array) ? innermost_token.verify_claims!(*claims) : innermost_token.verify_claims!(claims)
      tokens
    end

    private

    def validate_key_count!(keys)
      return if keys.length == tokens.length

      raise JWT::DecodeError, "Expected #{tokens.length} key configurations, got #{keys.length}"
    end
  end
end
