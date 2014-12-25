module JWA
  autoload :ES, 'jwa/ecdsa'
  autoload :HS, 'jwa/hmac'
  autoload :RS, 'jwa/rsassa'

  class Base
    def normalize_input(input)
      input = input.to_json unless input.is_a? String
      input
    end
    protected :normalize_input
  end

  def self.create(algorithm)
    klass = nil
    algo = algorithm.match(/(ES|HS|RS)(256|384|512)/)

    raise ArgumentError.new('Unsupported algorithm.') unless algo 

    case algo[1]
    when 'ES'
      klass = ES.new algo[2].to_i
    when 'HS'
      klass = HS.new algo[2].to_i
    when 'RS'
      klass = RS.new algo[2].to_i
    end

    klass
  end
end
