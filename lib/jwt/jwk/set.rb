# frozen_string_literal: true

module JWT
  module JWK
    class Set
      include Enumerable

      attr_reader :keys

      def initialize(jwks)
        jwks ||= {}

        @keys = case jwks
                when JWT::JWK::Set # Simple duplication
                  jwks.keys
                when JWT::JWK::KeyBase # Singleton
                  [jwks]
                when Hash
                  jwks = jwks.transform_keys(&:to_sym)
                  [*jwks[:keys]].map { |k| JWT::JWK.new k }
                when Array
                  jwks.map { |k| JWT::JWK.new k }
                else
                  raise ArgumentError, 'Can only create new JWKS from Hash, Array and JWK'
        end
      end

      def export(options = {})
        { keys: @keys.map { |k| k.export(options) } }
      end

      def each(&block)
        @keys.each(&block)
      end

      def select!(&block)
        return @keys.select! unless block

        self if @keys.select!(&block)
      end

      def reject!(&block)
        return @keys.reject! unless block

        self if @keys.reject!(&block)
      end

      alias filter! select!

      def size
        @keys.size
      end

      alias length size

      def merge(enum)
        @keys += JWT::JWK::Set.new(enum.collect)
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

      # For symbolic manipulation
      alias | union
      alias + union
      alias << add
    end
  end
end
