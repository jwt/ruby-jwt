# frozen_string_literal: true

require_relative 'hmac/secret'

module JWT
  module JWK
    module HMAC
      include KeyAlgorithm

      KTY = 'oct'.freeze
      KTYS = [KTY, String].freeze

      class << self
        def create(secret, kid = nil)
          Secret.new(secret, kid)
        end

        alias new create

        def import(jwk_data)
          jwk_k = jwk_data[:k] || jwk_data['k']
          jwk_kid = jwk_data[:kid] || jwk_data['kid']

          raise JWT::JWKError, 'Key format is invalid for HMAC' unless jwk_k

          create(jwk_k, jwk_kid)
        end
      end
    end
  end
end
