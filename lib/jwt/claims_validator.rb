require_relative './error'

module JWT
  class ClaimsValidator
    INTEGER_CLAIMS = %i[
      exp
      iat
      nbf
    ].freeze

    def initialize(payload)
      @payload = payload.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }
    end

    def validate!
      validate_int_claims

      true
    end

    private

    def validate_int_claims
      INTEGER_CLAIMS.each do |claim|
        validate_is_int(claim) if @payload.key?(claim)
      end
    end

    def validate_is_int(claim)
      raise InvalidPayload, "#{claim} claim must be an Integer but it is a #{@payload[claim].class}" unless @payload[claim].is_a?(Integer)
    end
  end
end
