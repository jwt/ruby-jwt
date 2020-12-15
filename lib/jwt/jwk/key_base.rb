# frozen_string_literal: true

module JWT
  module JWK
    class KeyBase
      def self.inherited(klass)
        ::JWT::JWK.classes << klass
      end
    end
  end
end
