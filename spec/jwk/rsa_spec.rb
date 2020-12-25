# frozen_string_literal: true

RSpec.describe JWT::JWK::RSA do
  let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

  describe '.new' do
    subject { described_class.new(keypair) }

    context 'when a keypair with both keys given' do
      let(:keypair) { rsa_key }
      it 'creates an instance of the class' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq true
      end
    end

    context 'when a keypair with only public key is given' do
      let(:keypair) { rsa_key.public_key }
      it 'creates an instance of the class' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq false
      end
    end
  end

  describe '#export' do
    subject { described_class.new(keypair).export }

    context 'when keypair with private key is exported' do
      let(:keypair) { rsa_key }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :n, :e, :kid)
        expect(subject).not_to include(:d, :p, :dp, :dq, :qi)
      end
    end

    context 'when keypair with public key is exported' do
      let(:keypair) { rsa_key.public_key }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :n, :e, :kid)
        expect(subject).not_to include(:d, :p, :dp, :dq, :qi)
      end
    end

    context 'when unsupported keypair is given' do
      let(:keypair) { 'key' }
      it 'raises an error' do
        expect { subject }.to raise_error(ArgumentError, 'keypair must be of type OpenSSL::PKey::RSA')
      end
    end

    context 'when private key is requested' do
      subject { described_class.new(keypair).export(include_private: true) }
      let(:keypair) { rsa_key }
      it 'returns a hash with the public AND private parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :n, :e, :kid, :d, :p, :q, :dp, :dq, :qi)
      end
    end
  end

  describe '.import' do
    subject { described_class.import(params) }
    let(:exported_key) { described_class.new(rsa_key).export }

    context 'when keypair is imported with symbol keys' do
      let(:params) { {e: exported_key[:e], n: exported_key[:n]} }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq false
        expect(subject.export).to eq(exported_key)
      end
    end

    context 'when keypair is imported with string keys from JSON' do
      let(:params) { {'e' => exported_key[:e], 'n' => exported_key[:n]} }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq false
        expect(subject.export).to eq(exported_key)
      end
    end

    context 'when private key is included in the data' do
      let(:exported_key) { described_class.new(rsa_key).export(include_private: true) }
      let(:params) { exported_key }
      it 'creates a complete keypair' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq true
      end
    end

    context 'when jwk_data is given without e and/or n' do
      let(:params) { { kty: "RSA" } }
      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, "Key format is invalid for RSA")
      end
    end
  end
end
