module JWT
  module Json
    if RUBY_VERSION >= "1.9" && !defined?(MultiJson)
      require 'json'

      def decode_json(encoded)
        JSON.parse(encoded)
      rescue JSON::ParserError
        raise JWT::DecodeError.new("Invalid segment encoding")
      end

      def encode_json(raw)
        JSON.generate(raw)
      end

    else
      require "multi_json"

      def decode_json(encoded)
        MultiJson.decode(encoded)
      rescue MultiJson::LoadError
        raise JWT::DecodeError.new("Invalid segment encoding")
      end

      def encode_json(raw)
        MultiJson.encode(raw)
      end
    end
  end
end