# frozen_string_literal: true

RSpec.describe JWT::Claims::IssuedAt do
  let(:payload) { { 'iat' => Time.now.to_f } }

  let(:options) { {} }

  subject(:verify!) { described_class.new(**options).verify!(context: SpecSupport::Token.new(payload: payload)) }

  context 'when iat is now' do
    it 'passes validation' do
      verify!
    end
  end

  context 'when iat is now as a integer' do
    let(:payload) { { 'iat' => Time.now.to_i } }

    it 'passes validation' do
      verify!
    end
  end
  context 'when the issuer clock is ahead of the verifier clock' do
    let(:now) { Time.at(1_609_459_200.5) }
    let(:payload) { { 'iat' => 1_609_459_201 } }

    before { allow(Time).to receive(:now) { now } }

    it 'fails validation' do
      expect { verify! }.to raise_error(JWT::InvalidIatError)
    end

    context 'when a leeway covering the drift is given' do
      let(:options) { { leeway: 1 } }

      it 'passes validation' do
        verify!
      end
    end

    context 'when a leeway smaller than the drift is given' do
      let(:payload) { { 'iat' => 1_609_459_260 } }
      let(:options) { { leeway: 1 } }

      it 'fails validation' do
        expect { verify! }.to raise_error(JWT::InvalidIatError)
      end
    end
  end

  context 'when iat is positive infinity' do
    let(:payload) { { 'iat' => Float::INFINITY } }

    it 'fails validation' do
      expect { verify! }.to raise_error(JWT::InvalidIatError)
    end
  end

  context 'when iat is not a number' do
    let(:payload) { { 'iat' => 'not_a_number' } }

    it 'fails validation' do
      expect { verify! }.to raise_error(JWT::InvalidIatError)
    end
  end

  context 'when iat is in the future' do
    let(:payload) { { 'iat' => Time.now.to_f + 120.0 } }

    it 'fails validation' do
      expect { verify! }.to raise_error(JWT::InvalidIatError)
    end
  end

  context 'when payload is a string containing iat' do
    let(:payload) { 'beautyexperts_nbf_iat' }

    it 'passes validation' do
      verify!
    end
  end
end
