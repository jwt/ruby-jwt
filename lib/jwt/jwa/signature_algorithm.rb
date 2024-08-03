# frozen_string_literal: true

module JWT
  module JWA
    module SignatureAlgorithm
      module ClassMethods
        def register_algorithm(*algos)
          ::JWT::JWA.register_algorithm(self, *algos)
        end

        def header(alg, *)
          { 'alg' => alg }
        end

        def raise_verify_error!(message)
          raise(DecodeError.new(message).tap { |e| e.set_backtrace(caller(1)) })
        end

        def raise_sign_error!(message)
          raise(EncodeError.new(message).tap { |e| e.set_backtrace(caller(1)) })
        end
      end

      def self.included(klass)
        klass.extend(ClassMethods)
      end
    end

    require_relative 'unsupported' # Require the unsupported algo as it's needed as a default for the rest

    class << self
      def register_algorithm(klass, *algos)
        algos.each do |algo|
          algorithms[algo.to_s.downcase] = Wrappers::RegisteredAlgorithm.new(algo, klass)
        end
      end

      def find(algo)
        algorithms[algo.to_s.downcase]
      end

      private

      def algorithms
        @algorithms ||= {}.tap { |h| h.default = Wrappers::RegisteredAlgorithm.new(nil, Unsupported) }
      end
    end
  end
end
