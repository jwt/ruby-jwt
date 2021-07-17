module JWT
  module Extension
    module ClassMethods
      def decode_payload(&block)
        @decode_payload_block = block
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
        ::JWT::DefaultOptions::DEFAULT_OPTIONS.merge(decode_payload_proc: @decode_payload_block).merge(given_options)
      end
    end
  end
end
