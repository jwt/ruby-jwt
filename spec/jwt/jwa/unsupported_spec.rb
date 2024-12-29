# frozen_string_literal: true

RSpec.describe JWT::JWA::Unsupported do
  describe '.sign' do
    it 'raises an error for unsupported signing method' do
      expect { described_class.sign('data', 'key') }.to raise_error(JWT::EncodeError, 'Unsupported signing method')
    end
  end

  describe '.verify' do
    it 'raises an error for unsupported algorithm' do
      expect { described_class.verify('data', 'signature', 'key') }.to raise_error(JWT::VerificationError, 'Algorithm not supported')
    end
  end
end
