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
        self[:kid]
      end

      def [](key)
        @common_parameters[key.to_sym]
      end

      def []=(key, value)
        @common_parameters[key.to_sym] = value
      end

      private

      attr_reader :common_parameters

      def initialize_kid(options)
        # kid can be specified outside common_parameters, takes priority
        self[:kid] = options[:kid] if options[:kid]

        return if self[:kid]

        # No kid given. Generate one from the public key
        kid_generator = options[:kid_generator] || ::JWT.configuration.jwk.kid_generator
        self[:kid] = kid_generator.new(self).generate
      end
    end
  end
end
