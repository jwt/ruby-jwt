# frozen_string_literal: true

require_relative './error'

module JWT
  class ClaimsValidator
    def initialize(payload)
      @payload = payload.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }
    end

    def validate
      validate_exp if @payload[:exp]

      true
    end

    private

    def validate_exp
      raise InvalidPayload, 'exp claim must be an integer' unless @payload[:exp].is_a?(Integer)
    end
  end
end
