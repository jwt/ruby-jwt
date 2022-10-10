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

        initialize_kid(options)
      end

      def kid
        @common_parameters[:kid]
      end

      attr_accessor :common_parameters

      private

      def initialize_kid(options)
        # kid can be specified outside common_parameters, takes priority
        @common_parameters[:kid] = options[:kid] if options[:kid]

        return if @common_parameters[:kid]

        # No kid given. Generate one from the public key
        kid_generator = options[:kid_generator] || ::JWT.configuration.jwk.kid_generator
        @common_parameters[:kid] = kid_generator.new(self).generate
      end
    end
  end
end
