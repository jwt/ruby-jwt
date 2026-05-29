# frozen_string_literal: true

module JWT
  # Represents a Nested JWT for creation, as defined in RFC 7519 Section 5.2.
  #
  # A Nested JWT wraps an existing JWT string as the payload of another signed JWT.
  # The payload is base64url-encoded directly (not JSON-encoded).
  #
  # @example Creating a Nested JWT
  #   inner = JWT::Token.new(payload: { user_id: 123 })
  #   inner.sign!(algorithm: 'HS256', key: 'inner_secret')
  #
  #   nested = JWT::NestedToken.new(inner.jwt)
  #   nested.sign!(algorithm: 'RS256', key: rsa_private_key)
  #   nested.jwt
  #
  # @example Multi-level nesting
  #   deeper = JWT::NestedToken.new(nested.jwt)
  #   deeper.sign!(algorithm: 'HS384', key: another_key)
  #   deeper.jwt
  #
  # @see https://datatracker.ietf.org/doc/html/rfc7519#section-5.2 RFC 7519 Section 5.2
  class NestedToken < Token
    def initialize(inner_jwt)
      super(payload: inner_jwt, header: { 'cty' => 'JWT' })
    end

    # Override to skip JSON encoding — payload is already a raw JWT string.
    def encoded_payload
      @encoded_payload ||= ::JWT::Base64.url_encode(payload)
    end
  end
end
