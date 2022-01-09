# frozen_string_literal: true

require 'securerandom'

RSpec.describe JWT::DSL do
  subject(:extension) do
    Class.new do
      include JWT
    end
  end

  let(:secret) { SecureRandom.hex }
  let(:payload) { { 'pay' => 'load'} }

  describe '.encode' do
    it { is_expected.to respond_to(:encode!) }

    context 'when algorithm is configured and no signing key is given or configured' do
      before do
        extension.algorithm('HS256')
      end

      it 'raises an error about missing signing key' do
        expect { extension.encode!(payload) }.to raise_error(::JWT::SigningKeyMissing, 'No key given for signing')
      end
    end

    context 'when no algorithm is configured and key is given as a option' do
      it 'raises an error about unsupported algoritm implementation' do
        expect { extension.encode!(payload, signing_key: secret) }.to raise_error(NotImplementedError, 'Unsupported signing method')
      end
    end

    context 'when algorithm and signing is configured' do
      before do
        extension.algorithm('HS256')
        extension.signing_key(secret)
      end

      it 'yields the same result as the raw encode' do
        expect(extension.encode!(payload)).to eq(::JWT.encode(payload, secret, 'HS256'))
      end
    end
  end
end
