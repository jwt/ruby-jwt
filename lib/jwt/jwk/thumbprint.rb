# frozen_string_literal: true

module JWT
  module JWK
    # https://tools.ietf.org/html/rfc7638
    class Thumbprint
      attr_reader :jwk
      def initialize(jwk)
        @jwk = jwk
      end

      def to_s
        JWT::Base64.url_encode(
          Digest::SHA256.digest(
            JSON.generate(
              jwk.members.sort.to_h
            )
          )
        )
      end
    end
  end
end
