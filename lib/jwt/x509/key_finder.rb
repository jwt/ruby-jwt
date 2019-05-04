module JWT
  module X509
    class KeyFinder
      attr_reader :public_key
      # @param [Hash] opts x509 options for finding key
      # @option opts [String] 'x5u' (not yet supported)
      # @option opts [Array<String>] 'x5c' x509 cert chain, where first is the cert used to sign
      # @option opts [String] 'x5t' (not yet supported)
      def initialize(opts)
        unless opts['x5c'].nil?
          der = ::Base64.decode64(opts['x5c'].first)
          @public_key = OpenSSL::X509::Certificate.new(der).public_key
        end
      end
    end
  end
end
