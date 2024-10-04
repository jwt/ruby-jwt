# frozen_string_literal: true

module JWT
  # Represents an encoded JWT token
  #
  # Processing an encoded and signed token:
  #
  #   token = JWT::Token.new(payload: {pay: 'load'})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #
  #   encoded_token = JWT::EncodedToken.new(token.jwt)
  #   encoded_token.verify_signature!algorithm: 'HS256', key: 'secret')
  #   encoded_token.payload # => {'pay' => 'load'}
  class EncodedToken
    include Claims::VerificationMethods

    # Returns the original token provided to the class.
    # @return [String] The JWT token.
    attr_reader :jwt

    # Initializes a new EncodedToken instance.
    #
    # @param jwt [String] the encoded JWT token.
    # @raise [ArgumentError] if the provided JWT is not a String.
    def initialize(jwt)
      raise ArgumentError 'Provided JWT must be a String' unless jwt.is_a?(String)

      @jwt = jwt
      @encoded_header, @encoded_payload, @encoded_signature = jwt.split('.')
      @signing_input = [encoded_header, encoded_payload].join('.')
    end

    # Returns the decoded signature of the JWT token.
    #
    # @return [String] the decoded signature.
    def signature
      @signature ||= ::JWT::Base64.url_decode(encoded_signature || '')
    end

    # Returns the encoded signature of the JWT token.
    #
    # @return [String] the encoded signature.
    attr_reader :encoded_signature

    # Returns the decoded header of the JWT token.
    #
    # @return [Hash] the header.
    def header
      @header ||= parse_and_decode(@encoded_header)
    end

    # Returns the encoded header of the JWT token.
    #
    # @return [String] the encoded header.
    attr_reader :encoded_header

    # Returns the payload of the JWT token.
    #
    # @return [Hash] the payload.
    def payload
      @payload ||= parse_and_decode(encoded_payload)
    end

    # Returns the encoded payload of the JWT token.
    #
    # @return [String] the encoded payload.
    attr_reader :encoded_payload

    # Returns the signing input of the JWT token.
    #
    # @return [String] the signing input.
    attr_reader :signing_input

    # Verifies the signature of the JWT token.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
    # @param key [String, Array<String>] the key(s) to use for verification.
    # @return [nil]
    # @raise [JWT::VerificationError] if the signature verification fails.
    def verify_signature!(algorithm:, key:)
      return if valid_signature?(algorithm: algorithm, key: key)

      raise JWT::VerificationError, 'Signature verification failed'
    end

    # Checks if the signature of the JWT token is valid.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
    # @param key [String, Array<String>] the key(s) to use for verification.
    # @return [Boolean] true if the signature is valid, false otherwise.
    def valid_signature?(algorithm:, key:)
      Array(JWA.resolve_and_sort(algorithms: algorithm, preferred_algorithm: header['alg'])).any? do |algo|
        Array(key).any? do |one_key|
          algo.verify(data: signing_input, signature: signature, verification_key: one_key)
        end
      end
    end

    alias to_s jwt

    private

    def parse_and_decode(segment)
      JWT::JSON.parse(::JWT::Base64.url_decode(segment))
    rescue ::JSON::ParserError
      raise JWT::DecodeError, 'Invalid segment encoding'
    end
  end
end
