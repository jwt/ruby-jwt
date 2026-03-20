# frozen_string_literal: true

module JWT
  # Represents an encoded Nested JWT for verification, as defined in RFC 7519 Section 5.2.
  #
  # Unwraps all nesting levels and provides an Enumerable interface over the token layers
  # (outermost to innermost).
  #
  # @example Verifying a Nested JWT
  #   nested = JWT::EncodedNestedToken.new(nested_jwt_string)
  #   nested.verify!(
  #     keys: [
  #       { algorithm: 'RS256', key: rsa_public },
  #       { algorithm: 'HS256', key: 'inner_secret' }
  #     ]
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

    def initialize(jwt)
      raise ArgumentError, 'Provided JWT must be a String' unless jwt.is_a?(String)

      @tokens = unwrap(jwt)
    end

    def each(&block)
      @tokens.each(&block)
    end

    def last
      @tokens.last
    end

    # Verifies signatures at each nesting level and claims on the innermost token.
    #
    # @param keys [Array<Hash>] key configurations ordered outermost to innermost.
    #   Each hash should contain :algorithm and :key (or :key_finder).
    # @param claims [Array<Symbol>, Hash, nil] claim verification options for the innermost token.
    # @return [self]
    # @raise [JWT::DecodeError] if key count doesn't match nesting depth.
    # @raise [JWT::VerificationError] if any signature verification fails.
    def verify!(keys:, claims: nil)
      raise JWT::DecodeError, "Expected #{count} key configurations, got #{keys.length}" unless keys.length == count

      each_with_index do |token, index|
        token.verify_signature!(algorithm: keys[index][:algorithm], key: keys[index][:key])
      end

      last.verify_claims!(*Array(claims).compact)
      self
    end

    private

    def unwrap(jwt)
      tokens = []
      current = jwt

      loop do
        raise JWT::DecodeError, "Nested JWT exceeds maximum depth of #{MAX_DEPTH}" if tokens.length >= MAX_DEPTH

        token = EncodedToken.new(current)
        tokens << token
        break unless token.header['cty']&.upcase == 'JWT'

        current = ::JWT::Base64.url_decode(token.encoded_payload)
      end

      tokens
    end
  end
end
