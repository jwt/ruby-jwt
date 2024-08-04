# frozen_string_literal: true

module JWT
  module Claims
    ValidationContext = Struct.new(:payload, keyword_init: true)

    class << self
      def verify!(payload, options)
        verify_expiration(payload, options)
        verify_not_before(payload, options)
        verify_iss(payload, options)
        verify_iat(payload, options)
        verify_jti(payload, options)
        verify_aud(payload, options)
        verify_sub(payload, options)
        verify_required_claims(payload, options)
      end

      def verify_aud(payload, options)
        return unless options[:verify_aud]

        Claims::Audience.new(expected_audience: options[:aud]).validate!(context: ValidationContext.new(payload: payload))
      end

      def verify_expiration(payload, options)
        return unless options[:verify_expiration]

        Claims::Expiration.new(leeway: options[:exp_leeway] || options[:leeway]).validate!(context: ValidationContext.new(payload: payload))
      end

      def verify_iat(payload, options)
        return unless options[:verify_iat]

        Claims::IssuedAt.new.validate!(context: ValidationContext.new(payload: payload))
      end

      def verify_iss(payload, options)
        return unless options[:verify_iss]

        Claims::Issuer.new(issuers: options[:iss]).validate!(context: ValidationContext.new(payload: payload))
      end

      def verify_jti(payload, options)
        return unless options[:verify_jti]

        Claims::JwtId.new(validator: options[:verify_jti]).validate!(context: ValidationContext.new(payload: payload))
      end

      def verify_not_before(payload, options)
        return unless options[:verify_not_before]

        Claims::NotBefore.new(leeway: options[:nbf_leeway] || options[:leeway]).validate!(context: ValidationContext.new(payload: payload))
      end

      def verify_sub(payload, options)
        return unless options[:verify_sub]
        return unless options[:sub]

        Claims::Subject.new(expected_subject: options[:sub]).validate!(context: ValidationContext.new(payload: payload))
      end

      def verify_required_claims(payload, options)
        return unless (options_required_claims = options[:required_claims])

        Claims::Required.new(required_claims: options_required_claims).validate!(context: ValidationContext.new(payload: payload))
      end
    end
  end
end

require_relative 'claims/audience'
require_relative 'claims/expiration'
require_relative 'claims/issued_at'
require_relative 'claims/issuer'
require_relative 'claims/jwt_id'
require_relative 'claims/not_before'
require_relative 'claims/numeric'
require_relative 'claims/required'
require_relative 'claims/subject'
