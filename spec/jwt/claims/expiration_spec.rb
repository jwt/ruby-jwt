# frozen_string_literal: true

RSpec.describe JWT::Claims::Expiration do
  let(:payload) { { 'exp' => (Time.now.to_i + 5) } }
  let(:leeway) { 0 }

  subject(:verify!) { described_class.new(leeway: leeway).verify!(context: SpecSupport::Token.new(payload: payload)) }

  context 'when token is expired' do
    let(:payload) { { 'exp' => (Time.now.to_i - 5) } }

    it 'must raise JWT::ExpiredSignature when the token has expired' do
      expect { verify! }.to(raise_error(JWT::ExpiredSignature))
    end
  end

  context 'when token is expired but some leeway is defined' do
    let(:payload) { { 'exp' => (Time.now.to_i - 5) } }
    let(:leeway) { 10 }

    it 'passes validation' do
      verify!
    end
  end

  context 'when token exp is set to current time' do
    let(:payload) { { 'exp' => Time.now.to_i } }

    it 'fails validation' do
      expect { verify! }.to(raise_error(JWT::ExpiredSignature))
    end
  end

  context 'when token is not a Hash' do
    let(:payload) { 'beautyexperts_nbf_iat' }
    it 'passes validation' do
      verify!
    end
  end

  ['never', '', ' ', 'NaN', '9999999999', '9999999999abc', nil, true, false, [], {}, Float::INFINITY, -Float::INFINITY, Float::NAN].each do |value|
    context "when exp is #{value.inspect}" do
      let(:payload) { { 'exp' => value } }

      it 'raises JWT::InvalidPayload' do
        expect { verify! }.to raise_error(JWT::InvalidPayload, 'exp claim must be a finite Numeric value')
      end
    end
  end
end
