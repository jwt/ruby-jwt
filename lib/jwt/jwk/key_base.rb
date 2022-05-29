# frozen_string_literal: true

module JWT
  module JWK
    class KeyBase
      def self.inherited(klass)
        super
        ::JWT::JWK.classes << klass
      end

      def initialize(options)
        options ||= {}

        if options.is_a?(String) # For backwards compatibility when kid was a String
          options = { kid: options }
        end

        @kid           = options[:kid]
        @kid_generator = options[:kid_generator] || ::JWT.configuration.jwk.kid_generator
      end

      def kid
        @kid ||= generate_kid
      end

      private

      attr_reader :kid_generator

      def generate_kid
        kid_generator.new(self).generate
      end
    end
  end
end
