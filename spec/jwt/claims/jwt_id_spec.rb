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

  context 'when payload is not a Hash' do
    [['x'], 42, nil, 'jti'].each do |non_hash_payload|
      context "when payload is #{non_hash_payload.inspect}" do
        let(:payload) { non_hash_payload }
        let(:validator_calls) { [] }

        it 'raises JWT::InvalidJtiError' do
          expect { verify! }.to raise_error(JWT::InvalidJtiError, 'Missing jti')
        end

        context 'when a validator taking the jti is given' do
          let(:validator) { ->(given_jti) { validator_calls << given_jti } }
          it 'raises JWT::InvalidJtiError without calling the validator' do
            expect { verify! }.to raise_error(JWT::InvalidJtiError, 'Missing jti')
            expect(validator_calls).to be_empty
          end
        end

        context 'when a validator taking the jti and the payload is given' do
          let(:validator) { ->(given_jti, given_payload) { validator_calls << [given_jti, given_payload] } }
          it 'raises JWT::InvalidJtiError without calling the validator' do
            expect { verify! }.to raise_error(JWT::InvalidJtiError, 'Missing jti')
            expect(validator_calls).to be_empty
          end
        end
      end
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

  context 'when jti validator is an object that responds to call but not to arity' do
    let(:validator_class) do
      Class.new do
        attr_reader :calls

        def initialize
          @calls = []
        end
      end
    end

    context 'when call takes the jti' do
      let(:validator) do
        Class.new(validator_class) do
          def call(jti)
            calls << [jti]
          end
        end.new
      end

      it 'calls it with the jti' do
        verify!
        expect(validator.calls).to eq([[jti]])
      end
    end

    context 'when call takes the jti and the payload' do
      let(:validator) do
        Class.new(validator_class) do
          def call(jti, payload)
            calls << [jti, payload]
          end
        end.new
      end

      it 'calls it with the jti and the payload' do
        verify!
        expect(validator.calls).to eq([[jti, payload]])
      end
    end
  end
end
