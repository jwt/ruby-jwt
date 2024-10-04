# frozen_string_literal: true

require_relative 'jwa'

module JWT
  class Encode
    def initialize(options)
      @token     = Token.new(payload: options[:payload], header: options[:headers])
      @key       = options[:key]
      @algorithm = options[:algorithm]
    end

    def segments
      @token.verify_claims!(:numeric)
      @token.sign!(algorithm: @algorithm, key: @key)
      @token.jwt
    end
  end
end
