# frozen_string_literal: true

require 'securerandom'

RSpec.describe JWT::DSL do
  subject(:extension) do
    secret_key = secret

    Class.new do
      include JWT
      algorithm 'HS256'
      key secret_key
    end
  end

  let(:secret) { SecureRandom.hex }
  let(:exp) { Time.now.to_i + 60 }
  let(:payload) { { 'pay' => 'load', 'exp' => exp } }
  let(:encoded_payload) { ::JWT.encode(payload, secret, 'HS256') }

  describe '.decode!' do
    it { is_expected.to respond_to(:decode!) }

    context 'when nothing but algorithm is defined' do
      it 'verifies a token and returns the data' do
        expect(extension.decode!(encoded_payload, key: secret)).to eq([payload, { 'alg' => 'HS256' }])
      end
    end

    context 'when a decode_payload block manipulates the payload' do
      before do
        extension.decode_payload do |raw_payload, _header, _signature|
          payload_content = JWT::JSON.parse(Base64.urlsafe_decode64(raw_payload))
          payload_content['pay'].reverse!
          payload_content
        end
      end

      it 'uses the defined decode_payload to process the raw payload' do
        expect(extension.decode!(encoded_payload).first['pay']).to eq('daol')
      end
    end

    context 'when block given' do
      it 'calls it with payload and header' do
        expect { |b| extension.decode!(encoded_payload, &b) }.to yield_with_args(payload, { 'alg' => 'HS256' })
      end
    end

    context 'when given block returns something' do
      it 'returns what the block returned' do
        expect(extension.decode!(encoded_payload) { '123' }).to eq('123')
      end
    end

    context 'when signing key is invalid' do
      it 'raises JWT::VerificationError' do
        expect { extension.decode!(encoded_payload, key: 'invalid') }.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end
    end

    context 'when algorithm is not matching the one in the token' do
      it 'raises JWT::VerificationError' do
        expect { extension.decode!(encoded_payload, algorithms: ['HS512']) }.to raise_error(JWT::IncorrectAlgorithm, 'Expected a different algorithm')
      end
    end

    context 'when one of the given algorithms match' do
      it 'raises JWT::VerificationError' do
        expect(extension.decode!(encoded_payload, algorithms: ['HS512', 'HS256'])).to eq([payload, { 'alg' => 'HS256' }])
      end
    end

    context 'when payload is invalid JSON' do
      before do
        extension.encode_payload do |payload|
          Base64.urlsafe_encode64(payload.inspect, padding: false)
        end
      end

      let(:encoded_payload) { extension.encode!(payload) }

      it 'raises JWT::DecodeError' do
        expect { extension.decode!(encoded_payload) }.to raise_error(JWT::DecodeError, 'Invalid segment encoding')
      end
    end

    context 'when token is expired' do
      let(:exp) { Time.now.to_i - 20 }

      it 'allows token to be 30 seconds overdue' do
        expect { extension.decode!(encoded_payload) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
      end
    end

    context 'when expiration_leeway is set to 30 seconds' do
      before do
        extension.expiration_leeway 30
      end

      let(:exp) { Time.now.to_i - 20 }

      it 'allows token to be 30 seconds overdue' do
        expect(extension.decode!(encoded_payload)).to eq([payload, { 'alg' => 'HS256' }])
      end
    end
  end
end
