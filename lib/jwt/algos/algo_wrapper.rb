# frozen_string_literal: true

module JWT
  module Algos
    class AlgoWrapper
      attr_reader :alg

      def initialize(alg, cls)
        @alg = alg
        @cls = cls
      end

      def sign(data:, key:)
        @cls.sign(@alg, data, key)
      end
    end
  end
end
