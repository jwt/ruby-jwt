module JWA
  extend self

  ALGORITHMS = %w(HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 none)

  class InvalidPayloadFormat < ArgumentError
  end

  class InvalidAlgorithm < ArgumentError
  end

  def sign(algorithm, data)
    check_algorithm algorithm
    check_data data
  end

  def verify(algorithm, data)
    check_algorithm algorithm
    check_data data
  end

  def check_algorithm(algorithm)
    raise JWA::InvalidAlgorithm.new("JWA: Given algorithm [#{algorithm.to_s}] is not part of the JWS supported algorithms.") unless ALGORITHMS.include? algorithm
  end

  private :check_algorithm

  def check_data(data)
    raise JWA::InvalidPayloadFormat.new('JWA: Given data is not a string.') unless data.is_a? String
  end

  private :check_data
end
