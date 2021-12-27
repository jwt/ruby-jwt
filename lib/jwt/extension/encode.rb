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
          key: self.signing_key,
          algorithm: self.algorithm,
          headers: options[:headers]
        ).segments
      end
    end
  end
end
