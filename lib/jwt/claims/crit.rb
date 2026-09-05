# frozen_string_literal: true

module JWT
  module Claims
    # Responsible of validation the crit header
    class Crit
      # Initializes a new Crit instance.
      #
      # @param expected_crits [String] the expected crit header values for the JWT token.
      # @param strict [Boolean] whether the crit header may contain only expected values.
      def initialize(expected_crits:, strict: false)
        @expected_crits = Array(expected_crits)
        @strict = strict
      end

      # Verifies the critical claim ('crit') in the JWT token header.
      #
      # @param context [Object] the context containing the JWT payload and header.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::InvalidCritError] if the crit claim is invalid.
      # @return [nil]
      def verify!(context:, **_args)
        raise(JWT::InvalidCritError, 'Crit header missing') unless context.header['crit']
        raise(JWT::InvalidCritError, 'Crit header should be an array') unless context.header['crit'].is_a?(Array)

        missing = (expected_crits - context.header['crit'])
        raise(JWT::InvalidCritError, "Crit header missing expected values: #{missing.join(', ')}") if missing.any?

        unexpected = (context.header['crit'] - expected_crits)
        raise(JWT::InvalidCritError, "Unsupported critical headers: #{unexpected.join(', ')}") if strict && unexpected.any?

        nil
      end

      private

      attr_reader :expected_crits, :strict
    end
  end
end
