# frozen_string_literal: true

module JWT
  module DSL
    module Keys
      def signing_key(value = nil, &block)
        @signing_key = value unless value.nil?
        @signing_key = block if block_given?
        @signing_key
      end

      def verification_key(value = nil, &block)
        @verification_key = value unless value.nil?
        @verification_key = block if block_given?
        @verification_key
      end

      def key(value = nil, &block)
        verification_key(value, &block)
        signing_key(value, &block)
      end
    end
  end
end
