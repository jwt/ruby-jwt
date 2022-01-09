# frozen_string_literal: true

require_relative 'dsl/keys'
require_relative 'dsl/decode'
require_relative 'dsl/encode'

module JWT
  module DSL
    def self.included(cls)
      cls.extend(JWT::DSL::Keys)
      cls.extend(JWT::DSL::Decode)
      cls.extend(JWT::DSL::Encode)
    end
  end
end
