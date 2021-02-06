module JWT
  module Algos
    module None
      module_function

      SUPPORTED = %w[none].freeze

      def verify(*); end

      def sign(*); end
    end
  end
end
