# frozen_string_literal: true

module JWT
  # Collection of security methods
  #
  # @see: https://github.com/rails/rails/blob/master/activesupport/lib/active_support/security_utils.rb
  module SecurityUtils
    module_function

    def verify_rsa(algorithm, public_key, signing_input, signature)
      public_key.verify(OpenSSL::Digest.new(algorithm.sub('RS', 'sha')), signature, signing_input)
    end

    def verify_ps(algorithm, public_key, signing_input, signature)
      formatted_algorithm = algorithm.sub('PS', 'sha')

      public_key.verify_pss(formatted_algorithm, signature, signing_input, salt_length: :auto, mgf1_hash: formatted_algorithm)
    end

    def asn1_to_raw(signature, public_key)
      byte_size = (public_key.group.degree + 7) / 8
      OpenSSL::ASN1.decode(signature).value.map { |value| value.value.to_s(2).rjust(byte_size, "\x00") }.join
    end

    def raw_to_asn1(signature, private_key)
      byte_size = (private_key.group.degree + 7) / 8
      sig_bytes = signature[0..(byte_size - 1)]
      sig_char = signature[byte_size..-1] || ''
      OpenSSL::ASN1::Sequence.new([sig_bytes, sig_char].map { |int| OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(int, 2)) }).to_der
    end
  end
end
