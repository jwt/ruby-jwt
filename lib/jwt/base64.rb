# frozen_string_literal: true

module JWT
  # Base64 encoding and decoding
  class Base64
    class << self
      # Encode a string with URL-safe Base64 complying with RFC 4648 (not padded).
      def url_encode(str)
        encoded = [str].pack('m0')
        encoded.chomp!('==') || encoded.chomp!('=')
        encoded.tr!('+/', '-_')
        encoded
      end

      # Decode a string with URL-safe Base64 complying with RFC 4648.
      # Deprecated support for RFC 2045 remains for now. ("All line breaks or other characters not found in Table 1 must be ignored by decoding software")
      def url_decode(str)
        if !str.end_with?('=') && str.length % 4 != 0
          str = str.ljust((str.length + 3) & ~3, '=')
          str.tr!('-_', '+/')
        else
          str = str.tr('-_', '+/')
        end
        str.unpack1('m0')
      rescue ArgumentError => e
        raise unless e.message == 'invalid base64'

        warn('[DEPRECATION] Invalid base64 input detected, could be because of invalid padding, trailing whitespaces or newline chars. Graceful handling of invalid input will be dropped in the next major version of ruby-jwt')
        str.unpack1('m')
      end
    end
  end
end
