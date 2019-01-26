require 'spec_helper'
require 'jwt/claims_validator'

RSpec.describe JWT::ClaimsValidator do
  describe '#validate!' do
    it 'returns true if the payload is valid' do
      valid_payload = { 'exp' => 12345 }
      subject = described_class.new(valid_payload)

      expect(subject.validate!).to eq(true)
    end

    shared_examples_for 'an integer claim' do |claim|
      it "raises an error when the value of the #{claim} claim is a string" do
        subject = described_class.new({ claim => '1' })
        expect { subject.validate! }.to raise_error JWT::InvalidPayload
      end

      it "raises an error when the value of the #{claim} claim is a Time object" do
        subject = described_class.new({ claim => Time.now })
        expect { subject.validate! }.to raise_error JWT::InvalidPayload
      end

      it "validates the #{claim} claim when the key is either a string or a symbol" do
        symbol = described_class.new({ claim.to_sym => true })
        expect { symbol.validate! }.to raise_error JWT::InvalidPayload

        string = described_class.new({ claim.to_s => true })
        expect { string.validate! }.to raise_error JWT::InvalidPayload
      end
    end

    context 'exp claim' do
      it_should_behave_like 'an integer claim', :exp
    end

    context 'iat claim' do
      it_should_behave_like 'an integer claim', :iat
    end

    context 'nbf claim' do
      it_should_behave_like 'an integer claim', :nbf
    end
  end
end
