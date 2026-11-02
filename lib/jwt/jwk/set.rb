# frozen_string_literal: true

require 'forwardable'

module JWT
  module JWK
    # JSON Web Key Set (JWKS) representation
    # https://tools.ietf.org/html/rfc7517
    class Set
      include Enumerable
      extend Forwardable

      attr_reader :keys

      def initialize(jwks = nil, options = {})
        @keys = case jwks
                when nil               then []
                when JWT::JWK::Set     then jwks.keys.dup
                when JWT::JWK::KeyBase then [jwks]
                when Hash              then build_supported_keys(jwks.transform_keys(&:to_sym)[:keys], options)
                when Array             then build_keys(jwks, options)
                else raise ArgumentError, 'Can only create new JWKS from Hash, Array and JWK'
                end
      end

      # Ensures a duplicated set owns its key collection. The keys themselves are
      # intentionally shared; only the collection is copied.
      def initialize_copy(other)
        super
        @keys = @keys.dup
      end

      def export(options = {})
        { keys: @keys.map { |k| k.export(options) } }
      end

      def_delegators :@keys, :each, :size, :delete, :dig

      def select!(&block)
        return @keys.select! unless block

        self if @keys.select!(&block)
      end

      def reject!(&block)
        return @keys.reject! unless block

        self if @keys.reject!(&block)
      end

      def uniq!(&block)
        self if @keys.uniq!(&block)
      end

      def merge(enum)
        @keys += JWT::JWK::Set.new(enum.to_a).keys
        self
      end

      def union(enum)
        dup.merge(enum)
      end

      def add(key)
        @keys << JWT::JWK.new(key)
        self
      end

      def ==(other)
        other.is_a?(JWT::JWK::Set) && keys.sort == other.keys.sort
      end

      alias eql? ==
      alias filter! select!
      alias length size
      # For symbolic manipulation
      alias | union
      alias + union
      alias << add

      private

      def build_keys(keys, options)
        [*keys].map { |key| JWT::JWK.new(key, nil, options) }
      end

      def build_supported_keys(keys, options)
        [*keys].each_with_object([]) do |key, arr|
          arr << JWT::JWK.new(key, nil, options)
        rescue JWT::UnsupportedKeyType
          nil
        end
      end
    end
  end
end
