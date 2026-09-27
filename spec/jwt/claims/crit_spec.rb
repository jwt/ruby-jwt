# frozen_string_literal: true

RSpec.describe JWT::Claims::Crit do
  subject(:verify!) { described_class.new(expected_crits: expected_crits).verify!(context: SpecSupport::Token.new(header: header)) }
  let(:expected_crits) { [] }
  let(:header) { {} }

  context 'in strict mode' do
    subject(:verify!) { described_class.new(expected_crits: ['b64'], strict: true).verify!(context: SpecSupport::Token.new(header: header)) }

    it 'accepts only supported critical headers' do
      header['crit'] = ['b64']
      expect(verify!).to be_nil
    end

    it 'rejects unexpected critical headers' do
      header['crit'] = %w[b64 unknown]
      expect { verify! }.to raise_error(JWT::InvalidCritError, 'Unsupported critical headers: unknown')
    end
  end

  context 'when header is missing' do
    it 'raises JWT::InvalidCritError' do
      expect { verify! }.to raise_error(JWT::InvalidCritError, 'Crit header missing')
    end
  end

  context 'when header is not an array' do
    let(:header) { { 'crit' => 'not_an_array' } }

    it 'raises JWT::InvalidCritError' do
      expect { verify! }.to raise_error(JWT::InvalidCritError, 'Crit header should be an array')
    end
  end

  context 'when header is an array and not containing the expected value' do
    let(:header) { { 'crit' => %w[crit1] } }
    let(:expected_crits) { %w[crit2] }
    it 'raises an InvalidCritError' do
      expect { verify! }.to raise_error(JWT::InvalidCritError, 'Crit header missing expected values: crit2')
    end
  end

  context 'when header is an array containing exactly the expected values' do
    let(:header) { { 'crit' => %w[crit1 crit2] } }
    let(:expected_crits) { %w[crit1 crit2] }
    it 'does not raise an error' do
      expect(verify!).to eq(nil)
    end
  end

  context 'when header is an array containing at least the expected values' do
    let(:header) { { 'crit' => %w[crit1 crit2 crit3] } }
    let(:expected_crits) { %w[crit1 crit2] }
    it 'does not raise an error' do
      expect(verify!).to eq(nil)
    end
  end
end
