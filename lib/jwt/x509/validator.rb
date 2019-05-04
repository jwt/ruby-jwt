module JWT
  module X509
    class Validator
      # @param [Hash] opts x509 options for finding key
      # @option opts [String] 'x5u' (not yet supported)
      # @option opts [Array<String>] 'x5c' x509 cert chain, where first is the cert used to sign
      # @option opts [String] 'x5t' (not yet supported)
      def initialize(opts)
        unless opts['x5c'].nil?
          signing_der = ::Base64.decode64((opts['x5c'].first))
          @signing_cert = OpenSSL::X509::Certificate.new(signing_der)
          len = opts['x5c'].length
          @cert_chain = opts['x5c'][1...len].map do |b64der|
            OpenSSL::X509::Certificate.new(::Base64.decode64(b64der))
          end
        end
      end

      def valid?
        return true if @cert_chain.nil? || @cert_chain.empty?

        store = OpenSSL::X509::Store.new
        @cert_chain.each do |cert|
          store.add_cert cert
        end
        store.verify @signing_cert
      end
    end
  end
end
