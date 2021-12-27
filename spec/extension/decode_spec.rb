# frozen_string_literal: true

require 'securerandom'

RSpec.describe JWT::Extension do
  subject(:extension) do
    Class.new do
      include JWT
    end
  end

  let(:secret) { SecureRandom.hex }
  let(:payload) { { 'pay' => 'load'} }
  let(:encoded_payload) { ::JWT.encode(payload, secret, 'HS256') }

  describe '.decode' do
    it { is_expected.to respond_to(:decode) }

    context 'when nothing special is defined' do
      it 'verifies a token and returns the data' do
        expect(extension.decode(encoded_payload, key: secret)).to eq(header: { 'alg' => 'HS256' }, payload: payload)
      end
    end

    context 'when a decode_payload block manipulates the payload' do
      before do
        extension.decode_payload do |_header, raw_payload, _signature|
          payload_content = JWT::JSON.parse(Base64.urlsafe_decode64(raw_payload))
          payload_content['pay'].reverse!
          Base64.urlsafe_encode64(JWT::JSON.generate(payload_content))
        end
      end

      it 'lets decode_payload process the raw payload before verifying' do
        expect(extension.decode(encoded_payload, key: secret)).to eq(header: { 'alg' => 'HS256' }, payload: {'pay' => 'daol'})
      end
    end
  end
end
