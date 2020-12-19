# frozen_string_literal: true

module JWT
  module JWK
    module KeyAlgorithm
      def self.included(klass)
        ::JWT::JWK.classes << klass
      end
    end
  end
end
