# frozen_string_literal: true

RSpec.describe JWT::JWA::Ps do
  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:data) { 'test data' }
  let(:ps256_instance) { described_class.new('PS256') }
  let(:ps384_instance) { described_class.new('PS384') }
  let(:ps512_instance) { described_class.new('PS512') }

  describe '#initialize' do
    it 'initializes with the correct algorithm and digest' do
      expect(ps256_instance.instance_variable_get(:@alg)).to eq('PS256')
      expect(ps256_instance.send(:digest_algorithm)).to eq('sha256')

      expect(ps384_instance.instance_variable_get(:@alg)).to eq('PS384')
      expect(ps384_instance.send(:digest_algorithm)).to eq('sha384')

      expect(ps512_instance.instance_variable_get(:@alg)).to eq('PS512')
      expect(ps512_instance.send(:digest_algorithm)).to eq('sha512')
    end
  end

  describe '#sign' do
    context 'with a valid RSA key' do
      it 'signs the data with PS256' do
        expect(ps256_instance.sign(data: data, signing_key: rsa_key)).not_to be_nil
      end

      it 'signs the data with PS384' do
        expect(ps384_instance.sign(data: data, signing_key: rsa_key)).not_to be_nil
      end

      it 'signs the data with PS512' do
        expect(ps512_instance.sign(data: data, signing_key: rsa_key)).not_to be_nil
      end
    end

    context 'with an invalid key' do
      it 'raises an error' do
        expect do
          ps256_instance.sign(data: data, signing_key: 'invalid_key')
        end.to raise_error(JWT::EncodeError, /The given key is a String. It has to be an OpenSSL::PKey::RSA instance./)
      end
    end
  end

  describe '#verify' do
    let(:ps256_signature) { ps256_instance.sign(data: data, signing_key: rsa_key) }
    let(:ps384_signature) { ps384_instance.sign(data: data, signing_key: rsa_key) }
    let(:ps512_signature) { ps512_instance.sign(data: data, signing_key: rsa_key) }

    context 'with a valid RSA key' do
      it 'verifies the signature with PS256' do
        expect(ps256_instance.verify(data: data, signature: ps256_signature, verification_key: rsa_key)).to be(true)
      end

      it 'verifies the signature with PS384' do
        expect(ps384_instance.verify(data: data, signature: ps384_signature, verification_key: rsa_key)).to be(true)
      end

      it 'verifies the signature with PS512' do
        expect(ps512_instance.verify(data: data, signature: ps512_signature, verification_key: rsa_key)).to be(true)
      end
    end

    context 'with an invalid signature' do
      it 'raises a verification error' do
        expect(ps256_instance.verify(data: data, signature: 'invalid_signature', verification_key: rsa_key)).to be(false)
      end
    end
  end

  context 'backwards compatibility' do
    it 'signs and verifies' do
      signature = described_class.sign('PS256', 'data', rsa_key)
      expect(described_class.verify('PS256', rsa_key, 'data', signature)).to be(true)
    end
  end
end
