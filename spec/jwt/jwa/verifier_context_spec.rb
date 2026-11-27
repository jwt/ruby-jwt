# frozen_string_literal: true

RSpec.describe JWT::JWA::VerifierContext do
  let(:hmac_secret) { 'a-shared-hmac-secret' }
  let(:data) { 'header.payload' }
  let(:signature) { JWT::JWA.resolve('HS256').sign(data: data, signing_key: hmac_secret) }
  let(:ec_key) { test_pkey('ec256-private.pem') }

  subject(:verify) { described_class.new(jwa: JWT::JWA.resolve('HS256'), keys: keys).verify(data: data, signature: signature) }

  context 'when a key of the wrong type comes before the right key' do
    let(:keys) { [ec_key, hmac_secret] }

    it { is_expected.to be(true) }
  end

  context 'when a key of the wrong type comes after the right key' do
    let(:keys) { [hmac_secret, ec_key] }

    it { is_expected.to be(true) }
  end

  context 'when a key of the wrong type comes before a key that does not match' do
    let(:keys) { [ec_key, 'not-the-secret'] }

    it { is_expected.to be(false) }
  end

  context 'when the only key is of the wrong type' do
    let(:keys) { [ec_key] }

    it 'raises the error for that key' do
      expect { verify }.to raise_error(JWT::VerificationKeyError, 'HMAC key expected to be a String')
    end
  end

  context 'when every key is of the wrong type' do
    let(:keys) { [ec_key, 42] }

    it 'raises the error for the first key' do
      expect { verify }.to raise_error(JWT::VerificationKeyError, 'HMAC key expected to be a String')
    end
  end

  context 'when no keys are given' do
    let(:keys) { [] }

    it { is_expected.to be(false) }
  end
end
