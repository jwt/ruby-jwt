# frozen_string_literal: true

RSpec.describe JWT::JWK do
  let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:ec_key) { OpenSSL::PKey::EC.new("secp384r1").generate_key }

  describe '.import' do
    let(:keypair) { rsa_key.public_key }
    let(:exported_key) { described_class.new(keypair).export }
    let(:params)  { exported_key }

    subject { described_class.import(params) }

    it 'creates a ::JWT::JWK::RSA instance' do
      expect(subject).to be_a ::JWT::JWK::RSA
      expect(subject.export).to eq(exported_key)
    end

    context 'parsed from JSON' do
      let(:params)  { exported_key }
      it 'creates a ::JWT::JWK::RSA instance from JSON parsed JWK' do
        expect(subject).to be_a ::JWT::JWK::RSA
        expect(subject.export).to eq(exported_key)
      end
    end

    context 'when keytype is not supported' do
      let(:params) { { kty: 'unsupported' } }

      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError)
      end
    end

    context 'when keypair with defined kid is imported' do
      it 'returns the predefined kid if jwt_data contains a kid' do
        params[:kid] = "CUSTOM_KID"
        expect(subject.export).to eq(params)
      end
    end
  end

  describe '.new' do
    subject { described_class.new(keypair) }

    context 'when RSA key is given' do
      let(:keypair) { rsa_key }
      it { is_expected.to be_a ::JWT::JWK::RSA }
    end

    context 'when secret key is given' do
      let(:keypair) { 'secret-key' }
      it { is_expected.to be_a ::JWT::JWK::HMAC }
    end

    context 'when EC key is given' do
      let(:keypair) { ec_key }
      it { is_expected.to be_a ::JWT::JWK::EC }
    end
  end
end
