# frozen_string_literal: true

require_relative 'error'

module JWT
  class ClaimsValidator
    def initialize(payload)
      Deprecations.warning('The ::JWT::ClaimsValidator class is deprecated and will be removed in the next major version of ruby-jwt')
      @payload = payload
    end

    def validate!
      Claims.verify_payload!(@payload, :numeric)
    end
  end
end
