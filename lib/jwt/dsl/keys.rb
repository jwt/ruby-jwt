# frozen_string_literal: true

module JWT
  module DSL
    # DSL methods for setting keys
    module Keys
      def signing_key(value = nil)
        @signing_key = value unless value.nil?
        @signing_key
      end

      def verification_key(value = nil)
        @verification_key = value unless value.nil?
        @verification_key
      end

      def key(value = nil)
        verification_key(value)
        signing_key(value)
      end
    end
  end
end
