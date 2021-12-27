# frozen_string_literal: true

module JWT
  module Extension
    module Decode
      def decode_payload(&block)
        @decode_payload = block if block_given?
        @decode_payload
      end

      def decode(payload, options = {})
        segments = ::JWT::Decode.new(payload,
                                     options.delete(:key),
                                     true,
                                     create_decode_options(options)).decode_segments
        {
          header: segments.last,
          payload: segments.first
        }
      end

      private

      def create_decode_options(given_options)
        ::JWT::DefaultOptions::DEFAULT_OPTIONS.merge(decode_payload_proc: self.decode_payload).merge(given_options)
      end
    end
  end
end
