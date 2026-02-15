# frozen_string_literal: true

require_relative 'encoded_token/claims_context'
require_relative 'encoded_token/segment_parser'
require_relative 'encoded_token/signature_verifier'

module JWT
  # Represents an encoded JWT token
  #
  # Processing an encoded and signed token:
  #
  #   token = JWT::Token.new(payload: {pay: 'load'})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #
  #   encoded_token = JWT::EncodedToken.new(token.jwt)
  #   encoded_token.verify_signature!(algorithm: 'HS256', key: 'secret')
  #   encoded_token.payload # => {'pay' => 'load'}
  class EncodedToken
    DEFAULT_CLAIMS = [:exp].freeze
    private_constant(:DEFAULT_CLAIMS)

    # Returns the original token provided to the class.
    # @return [String] The JWT token.
    attr_reader :jwt

    # Returns the encoded signature of the JWT token.
    # @return [String] the encoded signature.
    attr_reader :encoded_signature

    # Returns the encoded header of the JWT token.
    # @return [String] the encoded header.
    attr_reader :encoded_header

    # Sets or returns the encoded payload of the JWT token.
    # @return [String] the encoded payload.
    attr_accessor :encoded_payload

    # Initializes a new EncodedToken instance.
    #
    # @param jwt [String] the encoded JWT token.
    # @raise [ArgumentError] if the provided JWT is not a String.
    def initialize(jwt)
      raise ArgumentError, 'Provided JWT must be a String' unless jwt.is_a?(String)

      @jwt = jwt
      @allow_duplicate_keys = true
      @signature_verified = false
      @claims_verified = false
      @encoded_header, @encoded_payload, @encoded_signature = jwt.split('.')
    end

    # Enables strict duplicate key detection for this token.
    # When called, the token will raise JWT::DuplicateKeyError if duplicate keys
    # are found in the header or payload during parsing.
    #
    # @example
    #   token = JWT::EncodedToken.new(jwt_string)
    #   token.raise_on_duplicate_keys!
    #   token.header # May raise JWT::DuplicateKeyError
    #
    # @return [self]
    # @raise [JWT::DuplicateKeyError] if duplicate keys are found during subsequent parsing.
    # @raise [JWT::UnsupportedError] if the JSON gem version does not support duplicate key detection.
    def raise_on_duplicate_keys!
      raise JWT::UnsupportedError, 'Duplicate key detection requires JSON gem >= 2.13.0' unless JSON.supports_duplicate_key_detection?

      @allow_duplicate_keys = false
      @parser = nil
      self
    end

    # Returns the decoded signature of the JWT token.
    # @return [String] the decoded signature.
    def signature
      @signature ||= ::JWT::Base64.url_decode(encoded_signature || '')
    end

    # Returns the decoded header of the JWT token.
    # @return [Hash] the header.
    def header
      @header ||= parser.parse_and_decode(@encoded_header)
    end

    # Returns the payload of the JWT token. Access requires the signature and claims to have been verified.
    # @return [Hash] the payload.
    # @raise [JWT::DecodeError] if the signature or claims have not been verified.
    def payload
      raise JWT::DecodeError, 'Verify the token signature before accessing the payload' unless @signature_verified
      raise JWT::DecodeError, 'Verify the token claims before accessing the payload' unless @claims_verified

      unverified_payload
    end

    # Returns the payload of the JWT token without requiring the signature to have been verified.
    # @return [Hash] the payload.
    def unverified_payload
      @unverified_payload ||= decode_payload
    end

    # Returns the signing input of the JWT token.
    # @return [String] the signing input.
    def signing_input
      [encoded_header, encoded_payload].join('.')
    end

    # Verifies the token signature and claims.
    # By default it verifies the 'exp' claim.
    #
    # @example
    #  encoded_token.verify!(signature: { algorithm: 'HS256', key: 'secret' }, claims: [:exp])
    #
    # @param signature [Hash] the parameters for signature verification (see {#verify_signature!}).
    # @param claims [Array<Symbol>, Hash] the claims to verify (see {#verify_claims!}).
    # @return [nil]
    # @raise [JWT::DecodeError] if the signature or claim verification fails.
    def verify!(signature:, claims: nil)
      verify_signature!(**signature)
      claims.is_a?(Array) ? verify_claims!(*claims) : verify_claims!(claims)
      nil
    end

    # Verifies the token signature and claims.
    # By default it verifies the 'exp' claim.
    #
    # @param signature [Hash] the parameters for signature verification (see {#verify_signature!}).
    # @param claims [Array<Symbol>, Hash] the claims to verify (see {#verify_claims!}).
    # @return [Boolean] true if the signature and claims are valid, false otherwise.
    def valid?(signature:, claims: nil)
      valid_signature?(**signature) && (claims.is_a?(Array) ? valid_claims?(*claims) : valid_claims?(claims))
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
      return if valid_signature?(algorithm: algorithm, key: key, key_finder: key_finder)

      raise JWT::VerificationError, 'Signature verification failed'
    end

    # Checks if the signature of the JWT token is valid.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
    # @param key [String, Array<String>, JWT::JWK::KeyBase, Array<JWT::JWK::KeyBase>] the key(s) to use for verification.
    # @param key_finder [#call] an object responding to `call` to find the key for verification.
    # @return [Boolean] true if the signature is valid, false otherwise.
    def valid_signature?(algorithm: nil, key: nil, key_finder: nil)
      SignatureVerifier.new(self).verify(algorithm: algorithm, key: key, key_finder: key_finder).tap do |valid|
        @signature_verified = valid
      end
    end

    # Verifies the claims of the token.
    # @param options [Array<Symbol>, Hash] the claims to verify. By default, it checks the 'exp' claim.
    # @return [nil]
    # @raise [JWT::DecodeError] if the claims are invalid.
    def verify_claims!(*options)
      Claims::Verifier.verify!(ClaimsContext.new(self), *claims_options(options)).tap { @claims_verified = true }
    rescue StandardError
      @claims_verified = false
      raise
    end

    # Returns the errors of the claims of the token.
    # @param options [Array<Symbol>, Hash] the claims to verify. By default, it checks the 'exp' claim.
    # @return [Array<Symbol>] the errors of the claims.
    def claim_errors(*options)
      Claims::Verifier.errors(ClaimsContext.new(self), *claims_options(options))
    end

    # Returns whether the claims of the token are valid.
    # @param options [Array<Symbol>, Hash] the claims to verify. By default, it checks the 'exp' claim.
    # @return [Boolean] whether the claims are valid.
    def valid_claims?(*options)
      claim_errors(*claims_options(options)).empty?.tap { |verified| @claims_verified = verified }
    end

    alias to_s jwt

    private

    def claims_options(options)
      options.first.nil? ? DEFAULT_CLAIMS : options
    end

    def parser
      @parser ||= SegmentParser.new(allow_duplicate_keys: @allow_duplicate_keys)
    end

    def decode_payload
      raise JWT::DecodeError, 'Encoded payload is empty' if encoded_payload == ''

      return parser.parse_unencoded(encoded_payload).tap { verify_claims!(crit: ['b64']) } if header['b64'] == false

      parser.parse_and_decode(encoded_payload)
    end
  end
end
