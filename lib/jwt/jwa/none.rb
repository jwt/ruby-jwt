# frozen_string_literal: true

module JWT
  module JWA
    module None
      include JWT::JWA::SignatureAlgorithm
      SUPPORTED = %w[none].freeze

      register_algorithm(*SUPPORTED)

      class << self
        def sign(*)
          ''
        end

        def verify(*)
          true
        end
      end
    end
  end
end
