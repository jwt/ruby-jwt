module JWT
  # Collection of security methods
  #
  # @see: https://github.com/rails/rails/blob/master/activesupport/lib/active_support/security_utils.rb
  module SecurityUtils
    if defined?(OpenSSL.fixed_length_secure_compare)
      def fixed_length_secure_compare(a, b)
        OpenSSL.fixed_length_secure_compare(a, b)
      end
    else
      def fixed_length_secure_compare(a, b)
        raise ArgumentError, 'string length mismatch.' unless a.bytesize == b.bytesize

        l = a.unpack "C#{a.bytesize}"

        res = 0
        b.each_byte { |byte| res |= byte ^ l.shift }
        res.zero?
      end
    end

    module_function :fixed_length_secure_compare

    def secure_compare(a, b)
      a.bytesize == b.bytesize && fixed_length_secure_compare(a, b)
    end
    module_function :secure_compare
  end
end
