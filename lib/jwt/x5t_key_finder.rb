# frozen_string_literal: true

module JWT
  # If the x5t header thumbprint matches one of the trusted certificates,
  # returns the public key from that certificate.
  # See https://tools.ietf.org/html/rfc7515#section-4.1.7 and
  # https://tools.ietf.org/html/rfc7515#section-4.1.8
  class X5tKeyFinder
    def initialize(certificates)
      raise ArgumentError, 'Certificates must be specified' unless certificates.is_a?(Array)

      @certificates = certificates
    end

    def from(header)
      if header['x5t']
        x5t = header['x5t']
        digest_class = OpenSSL::Digest::SHA1
      elsif header['x5t#S256']
        x5t = header['x5t#S256']
        digest_class = OpenSSL::Digest::SHA256
      end

      raise JWT::DecodeError, 'x5t or x5t#S256 header parameter is required' unless x5t

      thumbprint = ::JWT::Base64.url_decode(x5t)
      matching_cert = @certificates.find do |cert|
        digest_class.new(cert.to_der).digest == thumbprint
      end

      raise JWT::VerificationError, 'No certificate matches the x5t thumbprint' unless matching_cert

      matching_cert.public_key
    end
  end
end
