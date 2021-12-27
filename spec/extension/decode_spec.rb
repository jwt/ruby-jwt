# frozen_string_literal: true

require 'securerandom'

RSpec.describe JWT::Extension do
  subject(:extension) do
    Class.new do
      include JWT
      algorithm 'HS256'
    end
  end

  let(:secret) { SecureRandom.hex }
  let(:payload) { { 'pay' => 'load'} }
  let(:encoded_payload) { ::JWT.encode(payload, secret, 'HS256') }

  describe '.decode!' do
    it { is_expected.to respond_to(:decode!) }

    context 'when nothing but algorithm is defined' do
      it 'verifies a token and returns the data' do
        expect(extension.decode!(encoded_payload, signing_key: secret)).to eq([payload, { 'alg' => 'HS256' }])
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
        expect(extension.decode!(encoded_payload, signing_key: secret)).to eq([{'pay' => 'daol'}, { 'alg' => 'HS256' }])
      end
    end
  end
end
