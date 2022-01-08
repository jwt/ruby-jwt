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

      def decode!(token, options = {})
        payload, header = Internals.decode!(token, options, self)

        return yield(payload, header) if block_given?

        [payload, header]
      end

      module Internals
        class << self
          def decode!(token, options, context)
            ::JWT::DecodeToken.new(token, build_decode_options(options, context)).decoded_segments
          end

          def build_decode_options(options, context)
            ::JWT::DefaultOptions::DEFAULT_OPTIONS.merge(key: options[:key] || context.verification_key || context.signing_key,
                                                         decode_payload_proc: context.decode_payload,
                                                         algorithms: (Array(context.algorithm) + Array(context.algorithms)).uniq,
                                                         jwks: context.jwk_resolver)
              .merge(options)
          end
        end
      end
    end
  end
end
