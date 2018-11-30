# frozen_string_literal: true

module JWT
  EncodeError             = Class.new(StandardError)
  DecodeError             = Class.new(StandardError)
  RequiredDependencyError = Class.new(StandardError)

  VerificationError  = Class.new(DecodeError)
  ExpiredSignature   = Class.new(DecodeError)
  IncorrectAlgorithm = Class.new(DecodeError)
  ImmatureSignature  = Class.new(DecodeError)
  InvalidIssuerError = Class.new(DecodeError)
  InvalidIatError    = Class.new(DecodeError)
  InvalidAudError    = Class.new(DecodeError)
  InvalidSubError    = Class.new(DecodeError)
  InvalidJtiError    = Class.new(DecodeError)
  InvalidPayload     = Class.new(DecodeError)

  JWKError           = Class.new(DecodeError)
end
