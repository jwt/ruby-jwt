# frozen_string_literal: true

module JWT
  module JWK
    class KeyAbstract
      attr_reader :keypair, :kid

      def initialize(keypair, kid = nil)
        @keypair = keypair
        @kid = kid
      end

      def private?
        raise NotImplementedError, "#{self.class} has not implemented method '#{__method__}'"
      end

      def public_key
        raise NotImplementedError, "#{self.class} has not implemented method '#{__method__}'"
      end

      def export(_options = {})
        raise NotImplementedError, "#{self.class} has not implemented method '#{__method__}'"
      end

      class << self
        def import(_jwk_data)
          raise NotImplementedError, "#{self.class} has not implemented method '#{__method__}'"
        end
      end
    end
  end
end
