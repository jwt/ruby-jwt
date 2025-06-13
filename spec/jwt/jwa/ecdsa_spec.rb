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

  let(:ecdsa_key) { test_pkey('ec256-private.pem') }
  let(:data) { 'test data' }
  let(:instance) { described_class.new('ES256', 'sha256') }

  describe '#verify' do
    context 'when the verification key is valid' do
      it 'returns true for a valid signature' do
        signature = instance.sign(data: data, signing_key: ecdsa_key)
        expect(instance.verify(data: data, signature: signature, verification_key: ecdsa_key)).to be true
      end

      it 'returns false for an invalid signature' do
        expect(instance.verify(data: data, signature: 'invalid_signature', verification_key: ecdsa_key)).to be false
      end
    end
    context 'when verification results in a OpenSSL::PKey::PKeyError error' do
      it 'raises a JWT::VerificationError' do
        allow(ecdsa_key).to receive(:dsa_verify_asn1).and_raise(OpenSSL::PKey::PKeyError.new('Error'))
        expect do
          instance.verify(data: data, signature: '', verification_key: ecdsa_key)
        end.to raise_error(JWT::VerificationError, 'Signature verification raised')
      end
    end
  end
end
