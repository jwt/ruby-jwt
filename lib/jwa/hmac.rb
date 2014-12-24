module JWA
  class HS < Base
    def initialize(bits)
      @algorithm = OpenSSL::Digest.new("sha#{bits}")
    end

    def sign(input, secret)
      OpenSSL::HMAC.digest(@algorithm, secret, normalize_input(input))
    end

    def verify(input, signature, secret)
      sign(input, secret) === signature
    end
  end
end
