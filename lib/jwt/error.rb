# frozen_string_literal: true

module JWT
  # The base error class for all JWT errors.
  class Error < StandardError; end

  # The EncodeError class is raised when there is an error encoding a JWT.
  class EncodeError < Error; end

  # The TokenError class is the base class for all errors related to token processing.
  class TokenError < Error; end

  # The MalformedTokenError class is raised when the token is structurally invalid.
  class MalformedTokenError < TokenError; end

  # The Base64DecodeError class is raised when there is an error decoding a Base64-encoded string.
  class Base64DecodeError < MalformedTokenError; end

  # The SignatureError class is the base class for signature and algorithm related errors.
  class SignatureError < TokenError; end

  # The VerificationError class is raised when there is an error verifying a JWT signature.
  class VerificationError < SignatureError; end

  # The IncorrectAlgorithm class is raised when the JWT algorithm is incorrect.
  class IncorrectAlgorithm < SignatureError; end

  # The UnsupportedEcdsaCurve class is raised when the ECDSA curve is unsupported.
  class UnsupportedEcdsaCurve < IncorrectAlgorithm; end

  # The ClaimValidationError class is the base class for all claim validation errors.
  class ClaimValidationError < TokenError; end

  # The ExpiredSignature class is raised when the JWT token has expired.
  class ExpiredSignature < ClaimValidationError; end

  # The ImmatureSignature class is raised when the JWT token is not yet valid (nbf).
  class ImmatureSignature < ClaimValidationError; end

  # The InvalidIssuerError class is raised when the JWT issuer is invalid.
  class InvalidIssuerError < ClaimValidationError; end

  # The InvalidIatError class is raised when the JWT issued at (iat) claim is invalid.
  class InvalidIatError < ClaimValidationError; end

  # The InvalidAudError class is raised when the JWT audience (aud) claim is invalid.
  class InvalidAudError < ClaimValidationError; end

  # The InvalidSubError class is raised when the JWT subject (sub) claim is invalid.
  class InvalidSubError < ClaimValidationError; end

  # The InvalidCritError class is raised when the JWT crit header is invalid.
  class InvalidCritError < ClaimValidationError; end

  # The InvalidJtiError class is raised when the JWT ID (jti) claim is invalid.
  class InvalidJtiError < ClaimValidationError; end

  # The InvalidPayload class is raised when the JWT payload is invalid.
  class InvalidPayload < ClaimValidationError; end

  # The MissingRequiredClaim class is raised when a required claim is missing from the JWT.
  class MissingRequiredClaim < ClaimValidationError; end

  # The JWKError class is raised when there is an error with the JSON Web Key (JWK).
  class JWKError < Error; end

  # Raised when a JWK uses a key type (kty) that this library does not support.
  class UnsupportedKeyType < JWKError; end

  # Backwards compatibility alias
  DecodeError = Error
end
