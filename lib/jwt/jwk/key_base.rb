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

        @common_parameters = options[:common_parameters] || {}
        @common_parameters = @common_parameters.transform_keys(&:to_sym) # Uniform interface
        @common_parameters[:kid] = options[:kid] if options[:kid] # kid can be specified outside common_parameters

        @kid_generator = options[:kid_generator] || ::JWT.configuration.jwk.kid_generator
      end

      def kid
        @common_parameters[:kid] ||= generate_kid
      end

      attr_accessor :common_parameters

      private

      attr_reader :kid_generator

      def generate_kid
        kid_generator.new(self).generate
      end
    end
  end
end
