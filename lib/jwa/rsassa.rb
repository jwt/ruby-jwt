module JWA
  class RS < Base
    def initialize(bits)
      @algorithm = OpenSSL::Digest.new("sha#{bits}")
    end

    def sign(input, rsa_key)
      rsa_key.sign(@algorithm, normalize_input(input))
    end

    def verify(input, signature, rsa_key)
      rsa_key.verify(@algorithm, signature, normalize_input(input))
    end
  end
end
