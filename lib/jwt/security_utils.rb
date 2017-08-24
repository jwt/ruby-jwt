module JWT
  # Collection of security methods
  #
  # @see: https://github.com/rails/rails/blob/master/activesupport/lib/active_support/security_utils.rb
  module SecurityUtils
    def secure_compare(left, right)
      left_bytesize = left.bytesize

      return false unless left_bytesize == right.bytesize

      unpacked_left = left.unpack "C#{left_bytesize}"
      result = 0
      right.each_byte { |byte| result |= byte ^ unpacked_left.shift }
      result.zero?
    end
    module_function :secure_compare
  end
end
