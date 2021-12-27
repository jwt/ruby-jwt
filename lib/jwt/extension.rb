# frozen_string_literal: true

require_relative 'extension/decode'
require_relative 'extension/encode'

module JWT
  module Extension
    def self.included(cls)
      cls.extend(JWT::Extension::Decode)
      cls.extend(JWT::Extension::Encode)
    end
  end
end
