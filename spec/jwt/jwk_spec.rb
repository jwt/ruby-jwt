# frozen_string_literal: true

RSpec.describe JWT::JWK do
  let(:rsa_key) { test_pkey('rsa-2048-private.pem') }
  let(:ec_key) { test_pkey('ec256k-private.pem') }

  describe '#inspect' do
    it 'shows only the public export for RSA and EC keys without changing private export' do
      [rsa_key, ec_key].each do |key|
        jwk = described_class.new(key)
        private_export = jwk.export(include_private: true)

        expect(jwk.inspect).to eq("#<#{jwk.class} public_export=#{jwk.export.inspect}>")
        expect(jwk.inspect).not_to include(private_export.fetch(:d))
        expect(jwk.export(include_private: true)).to eq(private_export)
      end
    end

    it 'does not expose an HMAC secret' do
      jwk = described_class.new('private-test-secret')

      expect(jwk.inspect).not_to include('private-test-secret', jwk.export(include_private: true).fetch(:k))
      expect(jwk.inspect).to include(jwk.kid)
    end
  end

  describe '.import' do
    let(:keypair) { rsa_key.public_key }
    let(:exported_key) { described_class.new(keypair).export }
    let(:params) { exported_key }

    subject { described_class.import(params) }

    it 'creates a ::JWT::JWK::RSA instance' do
      expect(subject).to be_a JWT::JWK::RSA
      expect(subject.export).to eq(exported_key)
    end

    context 'when number is given' do
      let(:params) { 1234 }
      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, 'Cannot create JWK from a Integer')
      end
    end

    context 'parsed from JSON' do
      let(:params)  { exported_key }
      it 'creates a ::JWT::JWK::RSA instance from JSON parsed JWK' do
        expect(subject).to be_a JWT::JWK::RSA
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
        params[:kid] = 'CUSTOM_KID'
        expect(subject.export).to eq(params)
      end
    end

    context 'when a common JWK parameter is specified' do
      it 'returns the defined common JWK parameter' do
        params[:use] = 'sig'
        expect(subject.export).to eq(params)
      end
    end
  end

  describe '.new' do
    let(:options) { nil }
    subject { described_class.new(keypair, options) }

    context 'when RSA key is given' do
      let(:keypair) { rsa_key }
      it { is_expected.to be_a JWT::JWK::RSA }
    end

    context 'when secret key is given' do
      let(:keypair) { 'secret-key' }
      it { is_expected.to be_a JWT::JWK::HMAC }
    end

    context 'when EC key is given' do
      let(:keypair) { ec_key }
      it { is_expected.to be_a JWT::JWK::EC }
    end

    context 'when kid is given' do
      let(:keypair) { rsa_key }
      let(:options) { 'CUSTOM_KID' }
      it 'sets the kid' do
        expect(subject.kid).to eq(options)
      end
    end

    context 'when a common parameter is given' do
      subject { described_class.new(keypair, params) }
      let(:keypair) { rsa_key }
      let(:params) { { 'use' => 'sig' } }
      it 'sets the common parameter' do
        expect(subject[:use]).to eq('sig')
      end
    end
  end

  describe '.[]' do
    let(:params) { { use: 'sig' } }
    let(:keypair) { rsa_key }
    subject { described_class.new(keypair, params) }

    it 'allows to read common parameters via the key-accessor' do
      expect(subject[:use]).to eq('sig')
    end

    it 'allows to set common parameters via the key-accessor' do
      subject[:use] = 'enc'
      expect(subject[:use]).to eq('enc')
    end

    it 'rejects key parameters as keys via the key-accessor' do
      expect { subject[:kty] = 'something' }.to raise_error(ArgumentError)
    end
  end
end
