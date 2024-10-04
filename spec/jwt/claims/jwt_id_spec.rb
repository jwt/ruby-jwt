# frozen_string_literal: true

RSpec.describe JWT::Claims::JwtId do
  let(:jti) { 'some-random-uuid-or-whatever' }
  let(:payload) { { 'jti' => jti } }
  let(:validator) { nil }

  subject(:verify!) { described_class.new(validator: validator).verify!(context: SpecSupport::Token.new(payload: payload)) }
  context 'when payload contains a jti' do
    it 'passes validation' do
      verify!
    end
  end

  context 'when payload is missing a jti' do
    let(:payload) { {} }
    it 'raises JWT::InvalidJtiError' do
      expect { verify! }.to raise_error(JWT::InvalidJtiError, 'Missing jti')
    end
  end

  context 'when payload contains a jti that is an empty string' do
    let(:jti) { '' }
    it 'raises JWT::InvalidJtiError' do
      expect { verify! }.to raise_error(JWT::InvalidJtiError, 'Missing jti')
    end
  end

  context 'when payload contains a jti that is a blank string' do
    let(:jti) { '   ' }
    it 'raises JWT::InvalidJtiError' do
      expect { verify! }.to raise_error(JWT::InvalidJtiError, 'Missing jti')
    end
  end

  context 'when jti validator is a proc returning false' do
    let(:validator) { ->(_jti) { false } }
    it 'raises JWT::InvalidJtiError' do
      expect { verify! }.to raise_error(JWT::InvalidJtiError, 'Invalid jti')
    end
  end

  context 'when jti validator is a proc returning true' do
    let(:validator) { ->(_jti) { true } }
    it 'passes validation' do
      verify!
    end
  end

  context 'when jti validator has 2 args' do
    let(:validator) { ->(_jti, _pl) { true } }
    it 'passes validation' do
      verify!
    end
  end

  context 'when jti validator has 2 args' do
    it 'the second arg is the payload' do
      described_class.new(validator: ->(_jti, pl) { expect(pl).to eq(payload) }).verify!(context: SpecSupport::Token.new(payload: payload))
    end
  end
end
