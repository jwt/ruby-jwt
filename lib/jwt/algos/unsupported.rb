module JWT
  module Algos
    module Unsupported
      module_function

      SUPPORTED = Object.new.tap { |object| object.define_singleton_method(:find) { |*| true } }
      def verify(*)
        raise JWT::VerificationError, 'Algorithm not supported'
      end

      def sign(*)
        raise NotImplementedError, 'Unsupported signing method'
      end
    end
  end
end
