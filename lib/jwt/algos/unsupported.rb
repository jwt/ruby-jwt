module JWT
  module Algos
    module Unsupported
      module_function

      SUPPORTED = [].freeze
      def verify(*)
        raise JWT::VerificationError, 'Algorithm not supported'
      end

      def sign(*)
        raise NotImplementedError, 'Unsupported signing method'
      end
    end
  end
end
