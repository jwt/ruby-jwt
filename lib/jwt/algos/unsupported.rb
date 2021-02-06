module JWT
  module Algos
    module Unsupported
      module_function

      SUPPORTED = []
      def verify(*)
        raise JWT::VerificationError, 'Algorithm not supported'
      end

      def sign(*)
        raise NotImplementedError, 'Unsupported signing method'
      end
    end
  end
end
