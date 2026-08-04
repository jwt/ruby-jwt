# frozen_string_literal: true

module JWT
  # Represents an encoded Nested JWT for verification, as defined in RFC 7519 Section 5.2.
  #
  # Unwraps all nesting levels and provides an Enumerable interface over the token layers
  # (outermost to innermost).
  #
  # @example Verifying a Nested JWT with a shared algorithm
  #   nested = JWT::EncodedNestedToken.new(nested_jwt_string)
  #   nested.verify!(algorithm: 'HS256', key: [outer_secret, inner_secret])
  #   nested.last.payload # => { 'user_id' => 123 }
  #
  # @example Verifying with mixed algorithms using key_finder
  #   nested = JWT::EncodedNestedToken.new(nested_jwt_string)
  #   nested.verify!(
  #     algorithm: %w[RS256 HS256],
  #     key_finder: ->(token) { key_map[token.header['alg']] }
  #   )
  #   nested.last.payload # => { 'user_id' => 123 }
  #
  # @example Inspecting layers
  #   nested = JWT::EncodedNestedToken.new(nested_jwt_string)
  #   nested.count          # => 2
  #   nested.map(&:header)  # => [outer_header, inner_header]
  #
  # @see https://datatracker.ietf.org/doc/html/rfc7519#section-5.2 RFC 7519 Section 5.2
  class EncodedNestedToken
    include Enumerable

    MAX_DEPTH = 10

    # @param jwt [String] the encoded JWT string.
    # @param max_depth [Integer] maximum nesting depth allowed.
    def initialize(jwt, max_depth: MAX_DEPTH)
      raise ArgumentError, 'Provided JWT must be a String' unless jwt.is_a?(String)

      @jwt = jwt
      @max_depth = max_depth
      @verified = false
    end

    def each(&block)
      tokens.each(&block)
    end

    # Returns the innermost token. Requires {#verify!} to have been called first.
    # @return [JWT::EncodedToken] the innermost token.
    # @raise [JWT::DecodeError] if the token has not been verified.
    def last
      raise JWT::DecodeError, 'Verify the token before accessing the innermost token' unless @verified

      tokens.last
    end

    # Verifies signatures at each nesting level and claims on the innermost token.
    #
    # Each token layer tries all provided algorithms and keys to find a match,
    # following the same pattern as {EncodedToken#verify_signature!}.
    #
    # Only the innermost token carries JSON claims (exp, iss, etc.).
    # Outer tokens' payloads are raw JWT strings, not JSON objects with claims.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to verify with.
    # @param key [String, Array<String>, JWT::JWK::KeyBase, Array<JWT::JWK::KeyBase>] the key(s) to verify with.
    # @param key_finder [#call] an object responding to `call` to find the key for verification.
    # @param claims [Array<Symbol>, Hash, nil] claim verification options for the innermost token.
    # @return [self]
    # @raise [JWT::VerificationError] if any signature verification fails.
    def verify!(algorithm:, key: nil, key_finder: nil, claims: nil)
      each do |token|
        token.verify_signature!(algorithm: algorithm, key: key, key_finder: key_finder)
      end

      @verified = true
      claims.is_a?(Array) ? last.verify_claims!(*claims) : last.verify_claims!(claims)
      self
    end

    private

    def tokens
      @tokens ||= unwrap(@jwt)
    end

    def unwrap(jwt)
      tokens = []
      current = jwt

      loop do
        raise JWT::DecodeError, "Nested JWT exceeds maximum depth of #{@max_depth}" if tokens.length >= @max_depth

        token = EncodedToken.new(current)
        tokens << token
        break unless token.header['cty']&.upcase == 'JWT'

        current = ::JWT::Base64.url_decode(token.encoded_payload)
      end

      tokens
    end
  end
end
