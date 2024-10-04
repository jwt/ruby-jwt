# frozen_string_literal: true

RSpec.describe JWT::Claims::Required do
  let(:payload) { { 'data' => 'value' } }

  subject(:verify!) { described_class.new(required_claims: required_claims).verify!(context: SpecSupport::Token.new(payload: payload)) }

  context 'when payload is missing the required claim' do
    let(:required_claims) { ['exp'] }
    it 'raises JWT::MissingRequiredClaim' do
      expect { verify! }.to raise_error JWT::MissingRequiredClaim, 'Missing required claim exp'
    end
  end

  context 'when payload has the required claims' do
    let(:payload) { { 'exp' => 'exp', 'custom_claim' => true } }
    let(:required_claims) { %w[exp custom_claim] }
    it 'passes validation' do
      verify!
    end
  end
end
