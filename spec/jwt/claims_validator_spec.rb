require 'spec_helper'
require 'jwt/claims_validator'

RSpec.describe JWT::ClaimsValidator do
  describe '#validate' do
    it 'returns true if the payload is valid' do
      valid_payload = { 'exp' => 12345 }
      subject = described_class.new(valid_payload)

      expect(subject.validate).to eq(true)
    end

    it 'raises an error when the value of the exp claim is a string' do
      subject = described_class.new({ exp: '1' })
      expect { subject.validate }.to raise_error JWT::InvalidPayload
    end

    it 'raises an error when the value of the exp claim is a Time object' do
      subject = described_class.new({ exp: Time.now })
      expect { subject.validate }.to raise_error JWT::InvalidPayload
    end

    it 'validates the exp when the exp key is either a string or a symbol' do
      symbol = described_class.new({ exp: true })
      expect { symbol.validate }.to raise_error JWT::InvalidPayload

      string = described_class.new({ 'exp' => true })
      expect { string.validate }.to raise_error JWT::InvalidPayload
    end
  end
end
