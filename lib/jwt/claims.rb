# frozen_string_literal: true

require_relative 'claims/audience'
require_relative 'claims/expiration'
require_relative 'claims/issued_at'
require_relative 'claims/issuer'
require_relative 'claims/jwt_id'
require_relative 'claims/not_before'
require_relative 'claims/numeric'
require_relative 'claims/required'
require_relative 'claims/subject'

module JWT
  module Claims
    VerificationContext = Struct.new(:payload, keyword_init: true)

    VERIFIERS = {
      verify_expiration: ->(options) { Claims::Expiration.new(leeway: options[:exp_leeway] || options[:leeway]) },
      verify_not_before: ->(options) { Claims::NotBefore.new(leeway: options[:nbf_leeway] || options[:leeway]) },
      verify_iss: ->(options) { Claims::Issuer.new(issuers: options[:iss]) },
      verify_iat: ->(*) { Claims::IssuedAt.new },
      verify_jti: ->(options) { Claims::JwtId.new(validator: options[:verify_jti]) },
      verify_aud: ->(options) { Claims::Audience.new(expected_audience: options[:aud]) },
      verify_sub: ->(options) { options[:sub] && Claims::Subject.new(expected_subject: options[:sub]) },
      required_claims: ->(options) { Claims::Required.new(required_claims: options[:required_claims]) }
    }.freeze

    class << self
      def verify!(payload, options)
        VERIFIERS.each do |key, verifier_builder|
          next unless options[key]

          verifier_builder&.call(options)&.verify!(context: VerificationContext.new(payload: payload))
        end
      end
    end
  end
end
