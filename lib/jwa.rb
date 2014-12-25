module JWA
#  autoload :ES, 'jwa/ecdsa'
  autoload :HS, 'jwa/hmac'
  autoload :RS, 'jwa/rsassa'
  autoload :Plain, 'jwa/none'

  class Base
    def normalize_input(input)
      input = input.to_json unless input.is_a? String
      input
    end
    protected :normalize_input
  end

  def self.create(algorithm)
    klass = nil
    algo = algorithm.match(/(HS|RS)(256|384|512)/)

    raise ArgumentError.new('Unsupported algorithm.') unless algo or algorithm == 'NONE'

    if algorithm == 'NONE'
      algo = []
      algo[1] = algorithm
    end

    case algo[1]
#    when 'ES'
#      klass = ES.new algo[2].to_i
    when 'HS'
      klass = HS.new algo[2].to_i
    when 'RS'
      klass = RS.new algo[2].to_i
    when 'NONE'
      klass = Plain.new
    end

    klass
  end
end
