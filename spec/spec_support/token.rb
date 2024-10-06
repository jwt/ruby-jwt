# frozen_string_literal: true

module SpecSupport
  Token = Struct.new(:payload, :header, keyword_init: true)
end
