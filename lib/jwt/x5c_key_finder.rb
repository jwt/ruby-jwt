# frozen_string_literal: true

require 'base64'
require 'jwt/error'

module JWT
  # If the x5c header certificate chain can be validated by trusted root
  # certificates, and none of the certificates are revoked, returns the public
  # key from the first certificate.
  # See https://tools.ietf.org/html/rfc7515#section-4.1.6
  class X5cKeyFinder
    def self.from(x5c_header_or_certificates, root_certificates, crls)
      store = build_store(root_certificates, crls)
      signing_certificate, *certificate_chain = parse_certificates(x5c_header_or_certificates)
      store_context = OpenSSL::X509::StoreContext.new(store, signing_certificate, certificate_chain)

      if store_context.verify
        signing_certificate.public_key
      else
        error = "Certificate verification failed: #{store_context.error_string}."
        error = "#{error} Certificate subject: #{store_context.current_cert.subject}." if store_context.current_cert

        raise JWT::VerificationError, error
      end
    end

    def self.parse_certificates(x5c_header_or_certificates)
      if x5c_header_or_certificates.all? { |obj| obj.is_a?(OpenSSL::X509::Certificate) }
        x5c_header_or_certificates
      else
        x5c_header_or_certificates.map do |encoded|
          OpenSSL::X509::Certificate.new(::Base64.strict_decode64(encoded))
        end
      end
    end
    private_class_method :parse_certificates

    def self.build_store(root_certificates, crls)
      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_ANY
      store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
      root_certificates.each { |certificate| store.add_cert(certificate) }
      crls && crls.each { |crl| store.add_crl(crl) }
      store
    end
    private_class_method :build_store
  end
end
