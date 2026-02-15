# frozen_string_literal: true

module JWT
  class EncodedToken
    # @private
    # Handles segment parsing and duplicate key detection.
    class SegmentParser
      def initialize(allow_duplicate_keys:)
        @allow_duplicate_keys = allow_duplicate_keys
      end

      def parse_and_decode(segment)
        parse(::JWT::Base64.url_decode(segment || ''))
      end

      def parse_unencoded(segment)
        parse(segment)
      end

      def parse(segment)
        JWT::JSON.parse(segment, allow_duplicate_keys: @allow_duplicate_keys)
      rescue ::JSON::ParserError
        raise JWT::DecodeError, 'Invalid segment encoding'
      end
    end
  end
end
