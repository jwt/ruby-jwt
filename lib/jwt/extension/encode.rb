# frozen_string_literal: true

module JWT
  module Extension
    module Encode
      def algorithm(value = nil)
        @algorithm = value unless value.nil?
        @algorithm
      end

      def encode_payload(&block)
        @encode_payload = block if block_given?
        @encode_payload
      end

      def encode!(payload, options = {})
        ::JWT::Encode.new(
          payload: payload,
          key: signing_key_from_options(options),
          algorithm: self.algorithm,
          encode_payload_proc: self.encode_payload,
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
