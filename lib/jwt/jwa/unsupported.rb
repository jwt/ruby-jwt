# frozen_string_literal: true

module JWT
  module JWA
    module Unsupported
      class << self
        def sign(*)
          raise NotImplementedError, 'Unsupported signing method'
        end

        def verify(*)
          raise JWT::VerificationError, 'Algorithm not supported'
        end
      end
    end
  end
end
