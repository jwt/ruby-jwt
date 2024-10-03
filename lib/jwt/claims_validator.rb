# frozen_string_literal: true

require_relative 'error'

module JWT
  class ClaimsValidator
    def initialize(payload)
      @payload = payload
    end

    def validate!
      Claims.verify_payload!(@payload, :numeric)
    end
  end
end
