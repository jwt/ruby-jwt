module JWA
  class HMAC
    def initialize(bits)
      @bits = bits
    end

    def sign(data, secret)
      validate_secret secret

      signature = OpenSSL::HMAC.digest OpenSSL::Digest.new("sha#{@bits}"), secret, data

      JWT::Base64.encode signature
    end

    def verify(data, signature, secret)
      signature === sign(data, secret)
    end

    def validate_secret(secret)
      raise JWA::MissingSecretOrKey.new('JWA: HMAC signing always requires a secret to be set.') if secret.length == 0
    end
  end
end
