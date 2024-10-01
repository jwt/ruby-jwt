# frozen_string_literal: true

RSpec.describe JWT::JWA::Ecdsa do
  describe '.curve_by_name' do
    subject { described_class.curve_by_name(curve_name) }

    context 'when secp256r1 is given' do
      let(:curve_name) { 'secp256r1' }
      it { is_expected.to eq(algorithm: 'ES256', digest: 'sha256') }
    end

    context 'when prime256v1 is given' do
      let(:curve_name) { 'prime256v1' }
      it { is_expected.to eq(algorithm: 'ES256', digest: 'sha256') }
    end

    context 'when secp521r1 is given' do
      let(:curve_name) { 'secp521r1' }
      it { is_expected.to eq(algorithm: 'ES512', digest: 'sha512') }
    end

    context 'when secp256k1 is given' do
      let(:curve_name) { 'secp256k1' }
      it { is_expected.to eq(algorithm: 'ES256K', digest: 'sha256') }
    end

    context 'when unknown is given' do
      let(:curve_name) { 'unknown' }
      it 'raises an error' do
        expect { subject }.to raise_error(JWT::UnsupportedEcdsaCurve)
      end
    end
  end

  context 'backwards compatibility' do
    it 'signs and verifies' do
      key = OpenSSL::PKey::EC.generate('prime256v1')
      signature = described_class.sign('ES256', 'data', key)
      expect(described_class.verify('ES256', key, 'data', signature)).to be(true)
    end
  end
end
