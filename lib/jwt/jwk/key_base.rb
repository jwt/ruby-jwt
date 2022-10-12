# frozen_string_literal: true

module JWT
  module JWK
    class KeyBase
      def self.inherited(klass)
        super
        ::JWT::JWK.classes << klass
      end

      def initialize(options, params = {})
        options ||= {}

        @parameters = params.transform_keys(&:to_sym) # Uniform interface

        # For backwards compatibility, kid_generator may be specified in the parameters
        options[:kid_generator] ||= @parameters.delete(:kid_generator)

        # Make sure the key has a kid
        kid_generator = options[:kid_generator] || ::JWT.configuration.jwk.kid_generator
        self[:kid] ||= kid_generator.new(self).generate
      end

      def kid
        self[:kid]
      end

      def [](key)
        @parameters[key.to_sym]
      end

      def []=(key, value)
        @parameters[key.to_sym] = value
      end

      private

      attr_reader :parameters
    end
  end
end
