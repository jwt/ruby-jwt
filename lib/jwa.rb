require 'jwa/hmac'
require 'jwa/none'
require 'jwa/rsassa'

module JWA
  extend self

  # The complete list of signing algorithms defined in the IETF JSON Web Algorithms (JWA) version 38
  # https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-38#section-3.1
  ALGORITHMS = %w(HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 none)

  # raises if the payload is not a string
  class InvalidPayloadFormat < ArgumentError
  end

  # raises if  a algorithm is called that is not defined in the specs
  # Info: all algorithms a case-sensitive
  class InvalidAlgorithm < ArgumentError
  end

  # raises if a secret or key is required but not provided in order to sign the data
  class MissingSecretOrKey < ArgumentError
  end

  # raises if a part of code is not implemented
  class NotImplemented < ArgumentError
  end

  def sign(algorithm, data, secret_or_private_key = '')
    algo, bits = validate_algorithm algorithm
    validate_data data

    case algo
      when 'HS'
        JWA::HMAC.new(bits).sign(data, secret_or_private_key)
      when 'RS'
        JWA::RSASSA.new(bits).sign(data, secret_or_private_key)
      when 'none'
        JWA::NONE.new.sign()
      else
        raise JWA::NotImplemented.new("JWA: #{algorithm} is not implemented yet.")
    end
  end

  def verify(algorithm, data, signature, secret_or_public_key = '')
    algo, bits = validate_algorithm algorithm
    validate_data data

    case algo
      when 'HS'
        JWA::HMAC.new(bits).verify(data, signature, secret_or_public_key)
      when 'RS'
        JWA::RSASSA.new(bits).verify(data, signature, secret_or_public_key)
      when 'none'
        JWA::NONE.new.verify()
      else
        raise JWA::NotImplemented.new("JWA: #{algorithm} is not implemented yet.")
    end
  end

  def validate_algorithm(algorithm)
    raise JWA::InvalidAlgorithm.new("JWA: Given algorithm [#{algorithm.to_s}] is not part of the JWS supported algorithms.") unless ALGORITHMS.include? algorithm

    match = algorithm.match(/(HS|RS|ES|PS|none)(\d+)?/)

    [match[1], match[2]]
  end

  private :validate_algorithm

  def validate_data(data)
    raise JWA::InvalidPayloadFormat.new('JWA: Given data is not a string.') unless data.is_a? String
  end

  private :validate_data
end
