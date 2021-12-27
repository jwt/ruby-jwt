# frozen_string_literal: true

module JWT
  module Extension
    module Encode
      def algorithm(value = nil)
        @algorithm = value unless value.nil?
        @algorithm
      end

      def signing_key(value = nil)
        @signing_key = value unless value.nil?
        @signing_key
      end

      def encode(payload, options = {})
        ::JWT::Encode.new(
          payload: payload,
          key: signing_key_from_options(options),
          algorithm: self.algorithm,
          headers: Array(options[:headers])
        ).segments
      end

      private

      def signing_key_from_options(options)
        key = options[:signing_key] || self.signing_key
        raise ::JWT::SigningKeyMissing, 'No key given for signing' if key.nil?

        key
      end
    end
  end
end
