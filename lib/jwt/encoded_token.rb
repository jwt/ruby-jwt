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
  #
  class EncodedToken
    include Claims::VerificationMethods

    # Returns the original token provided to the class.
    # @return [String] The JWT token.
    attr_reader :jwt

    # Initializes a new EncodedToken instance.
    #
    # @param jwt [String] the encoded JWT token.
    # @param enabled_crits [Array<String>] the list of enabled critical headers.
    # @param allow_unverified [Boolean] whether to allow access to payload for unverified tokens.
    # @raise [ArgumentError] if the provided JWT is not a String.
    # @raise [ArgumentError] if enabled_crits is not an Array.
    def initialize(jwt, enabled_crits: [])
      raise ArgumentError, 'Provided JWT must be a String' unless jwt.is_a?(String)
      raise ArgumentError, 'enabled_crits must be an Array' unless enabled_crits.is_a?(Array)

      @enabled_crits = enabled_crits
      @jwt = jwt
      @signature_verified = false
      @encoded_header, @encoded_payload, @encoded_signature = jwt.split('.')
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
    # @param allow_unverified [Boolean] whether to allow payloads to be accessed for unverified tokens.
    # @return [Hash] the payload.
    def payload
      @payload ||= decode_payload
    end

    # Sets or returns the encoded payload of the JWT token.
    #
    # @return [String] the encoded payload.
    # @param value [String] the encoded payload to set.
    attr_accessor :encoded_payload

    # Returns the signing input of the JWT token.
    #
    # @return [String] the signing input.
    def signing_input
      [encoded_header, encoded_payload].join('.')
    end

    # Verifies the signature of the JWT token.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
    # @param key [String, Array<String>] the key(s) to use for verification.
    # @param key_finder [#call] an object responding to `call` to find the key for verification.
    # @return [nil]
    # @raise [JWT::VerificationError] if the signature verification fails.
    # @raise [ArgumentError] if neither key nor key_finder is provided, or if both are provided.
    def verify_signature!(algorithm:, key: nil, key_finder: nil)
      raise ArgumentError, 'Provide either key or key_finder, not both or neither' if key.nil? == key_finder.nil?

      key ||= key_finder.call(self)

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

    # Verifies that a critical header is present and enabled.
    #
    # @param critical_header [String] the critical header to verify.
    # @return [nil]
    # @raise [InvalidCritError] if the critical header is missing or not enabled.
    def verify_crit!(crit)
      unless Array(header['crit']).include?(crit)
        raise InvalidCritError, "'#{crit}' missing from crit header"
      end

      return if Array(enabled_crits).include?(crit)

      raise InvalidCritError, "'#{crit}' not enabled for token instance"
    end

    alias to_s jwt

    private

    attr_reader :enabled_crits

    def decode_payload
      raise JWT::DecodeError, 'Encoded payload is empty' if encoded_payload == ''

      if unecoded_payload?
        verify_crit!('b64')
        return parse_unencoded(encoded_payload)
      end

      parse_and_decode(encoded_payload)
    end

    def unecoded_payload?
      header['b64'] == false
    end

    def parse_and_decode(segment)
      parse(::JWT::Base64.url_decode(segment))
    end

    def parse_unencoded(segment)
      parse(segment)
    end

    def parse(segment)
      JWT::JSON.parse(segment)
    rescue ::JSON::ParserError
      raise JWT::DecodeError, 'Invalid segment encoding'
    end
  end
end
