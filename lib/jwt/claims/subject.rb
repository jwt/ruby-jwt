# frozen_string_literal: true

module JWT
  module Claims
    # The Subject class is responsible for validating the subject claim ('sub') in a JWT token.
    class Subject
      # Initializes a new Subject instance.
      #
      # @param expected_subject [String] the expected subject for the JWT token.
      def initialize(expected_subject:)
        @expected_subject = expected_subject.to_s
      end

      # Verifies the subject claim ('sub') in the JWT token.
      #
      # @param context [Object] the context containing the JWT payload.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::InvalidSubError] if the subject claim is missing or does not match the expected subject,
      #   or if the expected subject is blank. A payload that is not a Hash has no subject claim.
      # @return [nil]
      def verify!(context:, **_args)
        sub = context.payload['sub'] if context.payload.is_a?(Hash)
        return if !sub.nil? && !expected_subject.strip.empty? && sub.to_s == expected_subject

        raise JWT::InvalidSubError, "Invalid subject. Expected #{expected_subject}, received #{sub.nil? ? '<none>' : sub}"
      end

      private

      attr_reader :expected_subject
    end
  end
end
