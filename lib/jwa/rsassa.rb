module JWA
  class RSASSA
    class KeyStrength < ArgumentError
    end

    def initialize(bits)
      @bits = bits
    end

    def sign(data, private_key)
      private_key = validate_key private_key

      signature = private_key.sign(OpenSSL::Digest.new("sha#{@bits}"), data)

      JWT::Base64.encode signature
    end

    def verify(data, signature, public_key)
      public_key = validate_key public_key

      public_key.verify(OpenSSL::Digest.new("sha#{@bits}"), JWT::Base64.decode(signature), data)
    end

    def validate_key(key)
      raise JWA::MissingSecretOrKey.new('JWA: RSA SHA signing and validating always requires a rsa key to be set.') if key.length == 0

      key = OpenSSL::PKey::RSA.new key

      strength = key.to_text.match(/(Public|Private)-Key: \((\d{1,4}) bit\)/)[2].to_i

      raise JWA::RSASSA::KeyStrength.new('JWA: RSA SHA: A key strength of minimum 2048 bit is required.') if strength < 2048

      key
    end

    private :validate_key
  end
end
