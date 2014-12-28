module JWA
  class HMAC
    def initialize(bits)

    end

    def sign(data, secret)
      validate_secret secret
    end

    def validate_secret(secret)
      raise JWA::MissingSecretOrKey.new('JWA: HMAC signing always requires a secret to be set.') if secret.length == 0
    end
  end
end
