require 'jwa/hmac'

module JWA
  extend self

  ALGORITHMS = %w(HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 none)

  class InvalidPayloadFormat < ArgumentError
  end

  class InvalidAlgorithm < ArgumentError
  end

  class MissingSecretOrKey < ArgumentError
  end

  def sign(algorithm, data, secret_or_private_key = '')
    algo, bits = validate_algorithm algorithm
    validate_data data

    case algo
      when 'HS'
        JWA::HMAC.new(bits).sign(data, secret_or_private_key)
      when 'RS'
      when 'ES'
      when 'PS'
      when 'none'
    end
  end

  def verify(algorithm, data, secret_or_private_key = '')
    validate_algorithm algorithm
    validate_data data
  end

  def validate_algorithm(algorithm)
    raise JWA::InvalidAlgorithm.new("JWA: Given algorithm [#{algorithm.to_s}] is not part of the JWS supported algorithms.") unless ALGORITHMS.include? algorithm #

    match = algorithm.match(/(HS|RS|ES|PS|none)(\d+)?/)

    [match[1], match[2]]
  end

  private :validate_algorithm

  def validate_data(data)
    raise JWA::InvalidPayloadFormat.new('JWA: Given data is not a string.') unless data.is_a? String
  end

  private :validate_data
end
