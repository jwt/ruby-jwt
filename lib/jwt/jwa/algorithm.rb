# frozen_string_literal: true

require_relative 'unsupported'

module JWT
  module JWA
    module Algorithm
      module ClassMethods
        def register_algorithm(*algos)
          ::JWT::JWA.register_algorithm(self, *algos)
        end

        def raise_verify_error!(message)
          raise(EncodeError.new(message).tap { |e| e.set_backtrace(caller(1)) })
        end

        def raise_sign_error!(message)
          raise(DecodeError.new(message).tap { |e| e.set_backtrace(caller(1)) })
        end
      end

      def self.included(klass)
        klass.extend(ClassMethods)
      end
    end

    class << self
      def register_algorithm(klass, *algos)
        algos.each do |algo|
          algorithms[algo.to_s.downcase] = [algo, klass]
        end
      end

      def find(algo)
        algorithms.fetch(algo.downcase) { [nil, Unsupported] }
      end

      private

      def algorithms
        @algorithms ||= {}
      end
    end
  end
end
