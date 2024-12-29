# frozen_string_literal: true

RSpec.describe JWT::JWA::Rsa do
  let(:rsa_key) { test_pkey('rsa-2048-private.pem') }
  let(:data) { 'test data' }
  let(:rsa_instance) { described_class.new('RS256') }

  describe '#initialize' do
    it 'initializes with the correct algorithm and digest' do
      expect(rsa_instance.instance_variable_get(:@alg)).to eq('RS256')
      expect(rsa_instance.send(:digest).name).to eq('SHA256')
    end
  end

  describe '#sign' do
    context 'with a valid RSA key' do
      it 'signs the data' do
        signature = rsa_instance.sign(data: data, signing_key: rsa_key)
        expect(signature).not_to be_nil
      end
    end

    context 'with a key length less than 2048 bits' do
      let(:rsa_key) { OpenSSL::PKey::RSA.generate(2047) }

      it 'raises an error' do
        expect do
          rsa_instance.sign(data: data, signing_key: rsa_key)
        end.to raise_error(JWT::EncodeError, 'The key length must be greater than or equal to 2048 bits')
      end
    end

    context 'with an invalid key' do
      it 'raises an error' do
        expect do
          rsa_instance.sign(data: data, signing_key: 'invalid_key')
        end.to raise_error(JWT::EncodeError, /The given key is a String. It has to be an OpenSSL::PKey::RSA instance/)
      end
    end
  end

  describe '#verify' do
    let(:signature) { rsa_instance.sign(data: data, signing_key: rsa_key) }

    context 'with a valid RSA key' do
      it 'returns true' do
        expect(rsa_instance.verify(data: data, signature: signature, verification_key: rsa_key)).to be(true)
      end
    end

    context 'with an invalid signature' do
      it 'returns false' do
        expect(rsa_instance.verify(data: data, signature: 'invalid_signature', verification_key: rsa_key)).to be(false)
      end
    end

    context 'with an invalid key' do
      it 'returns false' do
        expect(rsa_instance.verify(data: data, signature: 'invalid_signature', verification_key: OpenSSL::PKey::RSA.generate(2048))).to be(false)
      end
    end
  end
end
