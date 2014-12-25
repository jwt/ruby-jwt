module JWA
  class Plain < Base
    def initialize
    end

    def sign(input)
      normalize_input input
    end

    def verify(input, signature)
      signature === sign(input)
    end
  end
end
