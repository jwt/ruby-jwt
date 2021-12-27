# frozen_string_literal: true

module JWT
  module Extension
    module Decode
      def decode_payload(&block)
        @decode_payload = block if block_given?
        @decode_payload
      end

      def algorithms(value = nil)
        @algorithms = value unless value.nil?
        @algorithms
      end

      def jwk_resolver(&block)
        @jwk_resolver = block if block_given?
        @jwk_resolver
      end

      def decode!(payload, options = {})
        ::JWT::Decode.new(payload,
                          decode_signing_key_from_options(options),
                          true,
                          create_decode_options(options)).decode_segments
      end

      private

      def decode_signing_key_from_options(options)
        options[:signing_key] || self.signing_key
      end

      def create_decode_options(given_options)
        ::JWT::DefaultOptions::DEFAULT_OPTIONS.merge(decode_payload_proc: self.decode_payload,
                                                     algorithms: self.decoding_algorithms,
                                                     jwks: self.jwk_resolver)
          .merge(given_options)
      end

      def decoding_algorithms
        (Array(self.algorithm) + Array(self.algorithms)).uniq
      end
    end
  end
end
