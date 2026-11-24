# frozen_string_literal: true

RSpec.describe JWT::Claims::NotBefore do
  let(:payload) { { 'nbf' => (Time.now.to_i + 5) } }

  describe '#verify!' do
    context 'when nbf is in the future' do
      it 'raises JWT::ImmatureSignature' do
        expect { described_class.new(leeway: 0).verify!(context: SpecSupport::Token.new(payload: payload)) }.to raise_error(JWT::ImmatureSignature)
      end
    end

    context 'when nbf is in the past' do
      let(:payload) { { 'nbf' => (Time.now.to_i - 5) } }

      it 'does not raise error' do
        expect { described_class.new(leeway: 0).verify!(context: SpecSupport::Token.new(payload: payload)) }.not_to raise_error
      end
    end

    context 'when leeway is given' do
      it 'does not raise error' do
        expect { described_class.new(leeway: 10).verify!(context: SpecSupport::Token.new(payload: payload)) }.not_to raise_error
      end
    end

    ['never', '', ' ', 'NaN', '1000', nil, true, false, [], {}, Float::INFINITY, -Float::INFINITY, Float::NAN].each do |value|
      context "when nbf is #{value.inspect}" do
        it 'raises JWT::InvalidPayload' do
          expect { described_class.new(leeway: 0).verify!(context: SpecSupport::Token.new(payload: { 'nbf' => value })) }.to raise_error(JWT::InvalidPayload, 'nbf claim must be a finite Numeric value')
        end
      end
    end

    context 'when decoding a signed token with a non-numeric nbf' do
      let(:key) { 'a' * 32 }
      let(:token) { JWT::Token.new(payload: { nbf: 'never' }).tap { |t| t.sign!(algorithm: 'HS256', key: key) }.jwt }

      it 'rejects the token' do
        expect { JWT.decode(token, key, true, algorithm: 'HS256') }.to raise_error(JWT::InvalidPayload)
      end

      it 'accepts the token when nbf verification is disabled' do
        expect { JWT.decode(token, key, true, algorithm: 'HS256', verify_not_before: false) }.not_to raise_error
      end
    end
  end
end
