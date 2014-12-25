module JWA
  class ES < Base
    def initialize(bits)
      @algorithm = OpenSSL::Digest.new("sha#{bits}")
    end

    def sign(input, ec_key)
      ec_key.sign(@algorithm, normalize_input(input))
    end

    def verify(input, signature, ec_key)
      ec_key.verify(@algorithm, signature, normalize_input(input))
    end
  end
end
