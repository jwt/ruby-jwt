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
              headers: options[:headers],
              algorithm: context.algorithm
            }

            if opts[:algorithm].is_a?(String) && opts[:key].nil?
              raise ::JWT::SigningKeyMissing, 'No key given for signing'
            end

            opts
          end
        end
      end
    end
  end
end
