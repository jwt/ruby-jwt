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

    context 'when payload is not a Hash' do
      let(:payload) { 'beautyexperts_nbf_iat' }

      it 'does not raise error' do
        expect { described_class.new(leeway: 0).verify!(context: SpecSupport::Token.new(payload: payload)) }.not_to raise_error
      end
    end

    context 'when nbf is not a Numeric' do
      { true => 'TrueClass', ['x'] => 'Array', {} => 'Hash', '1700000000' => 'String' }.each do |nbf, type|
        context "when nbf is a #{type}" do
          let(:payload) { { 'nbf' => nbf } }

          it 'raises JWT::InvalidPayload' do
            expect { described_class.new(leeway: 0).verify!(context: SpecSupport::Token.new(payload: payload)) }.to raise_error(JWT::InvalidPayload, "nbf claim must be a Numeric value but it is a #{type}")
          end
        end
      end
    end
  end
end
