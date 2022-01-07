# frozen_string_literal: true

module JWT
  module Extension
    module Encode
      def algorithm(value = nil)
        @algorithm = value unless value.nil?
        @algorithm
      end

      def encode_payload(&block)
        @encode_payload = block if block_given?
        @encode_payload
      end

      def encode!(payload, options = {})
        Internals.encode!(payload, options, self)
      end

      module Internals
        class << self
          def encode!(payload, options, context)
            ::JWT::Encode.new(build_options(payload, options, context)).segments
          end

          def build_options(payload, options, context)
            opts = {
              payload: payload,
              key: options[:key] || context.signing_key,
              encode_payload_proc: context.encode_payload,
              headers: Array(options[:headers])
            }

            if (algo = context.algorithm).is_a?(String)
              opts[:algorithm] = algo
              raise ::JWT::SigningKeyMissing, 'No key given for signing' if opts[:key].nil?
            else
              opts[:algorithm_implementation] = algo
            end

            opts
          end
        end
      end
    end
  end
end