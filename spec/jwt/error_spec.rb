# frozen_string_literal: true

RSpec.describe 'JWT error hierarchy' do
  context 'base classes' do
    it 'JWT::Error inherits from StandardError' do
      expect(JWT::Error).to be < StandardError
    end

    it 'JWT::EncodeError inherits from JWT::Error' do
      expect(JWT::EncodeError).to be < JWT::Error
    end

    it 'JWT::TokenError inherits from JWT::Error' do
      expect(JWT::TokenError).to be < JWT::Error
    end
  end

  context 'backwards compatibility' do
    it 'JWT::DecodeError is an alias for JWT::Error' do
      expect(JWT::DecodeError).to eq(JWT::Error)
    end
  end

  context 'malformed token errors' do
    it 'JWT::MalformedTokenError inherits from JWT::TokenError' do
      expect(JWT::MalformedTokenError).to be < JWT::TokenError
    end

    it 'JWT::Base64DecodeError inherits from JWT::MalformedTokenError' do
      expect(JWT::Base64DecodeError).to be < JWT::MalformedTokenError
    end
  end

  context 'signature errors' do
    it 'JWT::SignatureError inherits from JWT::TokenError' do
      expect(JWT::SignatureError).to be < JWT::TokenError
    end

    it 'JWT::VerificationError inherits from JWT::SignatureError' do
      expect(JWT::VerificationError).to be < JWT::SignatureError
    end

    it 'JWT::IncorrectAlgorithm inherits from JWT::SignatureError' do
      expect(JWT::IncorrectAlgorithm).to be < JWT::SignatureError
    end

    it 'JWT::UnsupportedEcdsaCurve inherits from JWT::IncorrectAlgorithm' do
      expect(JWT::UnsupportedEcdsaCurve).to be < JWT::IncorrectAlgorithm
    end
  end

  context 'claim validation errors' do
    it 'JWT::ClaimValidationError inherits from JWT::TokenError' do
      expect(JWT::ClaimValidationError).to be < JWT::TokenError
    end

    %i[
      ExpiredSignature
      ImmatureSignature
      InvalidIssuerError
      InvalidIatError
      InvalidAudError
      InvalidSubError
      InvalidCritError
      InvalidJtiError
      InvalidPayload
      MissingRequiredClaim
    ].each do |error_class|
      it "JWT::#{error_class} inherits from JWT::ClaimValidationError" do
        expect(JWT.const_get(error_class)).to be < JWT::ClaimValidationError
      end
    end
  end

  context 'JWK errors' do
    it 'JWT::JWKError inherits from JWT::Error' do
      expect(JWT::JWKError).to be < JWT::Error
    end
  end

  context 'error groups do not overlap' do
    it 'claim validation errors are not signature errors' do
      expect(JWT::ClaimValidationError).not_to be <= JWT::SignatureError
      expect(JWT::SignatureError).not_to be <= JWT::ClaimValidationError
    end

    it 'claim validation errors are not malformed token errors' do
      expect(JWT::ClaimValidationError).not_to be <= JWT::MalformedTokenError
      expect(JWT::MalformedTokenError).not_to be <= JWT::ClaimValidationError
    end

    it 'signature errors are not malformed token errors' do
      expect(JWT::SignatureError).not_to be <= JWT::MalformedTokenError
      expect(JWT::MalformedTokenError).not_to be <= JWT::SignatureError
    end
  end
end
