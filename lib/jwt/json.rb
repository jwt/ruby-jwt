module JWT
  module Json

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