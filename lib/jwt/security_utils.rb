module JWT
  # Collection of security methods
  #
  # @see: https://github.com/rails/rails/blob/master/activesupport/lib/active_support/security_utils.rb
  module SecurityUtils
    module_function

    def secure_compare(left, right)
      left_bytesize = left.bytesize

      return false unless left_bytesize == right.bytesize

      unpacked_left = left.unpack "C#{left_bytesize}"
      result = 0
      right.each_byte { |byte| result |= byte ^ unpacked_left.shift }
      result.zero?
    end

    def verify_ps(algorithm, public_key, signing_input, signature)
      formatted_algorithm = algorithm.sub('PS', 'sha')

      public_key.verify_pss(formatted_algorithm, signature, signing_input, salt_length: :auto, mgf1_hash: formatted_algorithm)
    end
  end
end
