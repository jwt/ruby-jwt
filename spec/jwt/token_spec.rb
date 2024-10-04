# frozen_string_literal: true

RSpec.describe JWT::Token do
  let(:payload) { { 'pay' => 'load' } }
  let(:header) { {} }

  subject(:token) { described_class.new(payload: payload, header: header) }

  describe '#sign!' do
    it 'signs the token' do
      token.sign!(algorithm: 'HS256', key: 'secret')

      expect(JWT::EncodedToken.new(token.jwt).valid_signature?(algorithm: 'HS256', key: 'secret')).to be(true)
    end

    context 'when signed twice' do
      before do
        token.sign!(algorithm: 'HS256', key: 'secret')
      end

      it 'raises' do
        expect { token.sign!(algorithm: 'HS256', key: 'secret') }.to raise_error(JWT::EncodeError)
      end
    end
  end

  describe '#jwt' do
    context 'when token is signed' do
      before do
        token.sign!(algorithm: 'HS256', key: 'secret')
      end

      it 'returns a signed and encoded token' do
        expect(token.jwt).to eq('eyJhbGciOiJIUzI1NiJ9.eyJwYXkiOiJsb2FkIn0.UEhDY1Qlj29ammxuVRA_-gBah4qTy5FngIWg0yEAlC0')
        expect(JWT.decode(token.jwt, 'secret', true, algorithm: 'HS256')).to eq([{ 'pay' => 'load' }, { 'alg' => 'HS256' }])
      end
    end

    context 'when token is not signed' do
      it 'returns a signed and encoded token' do
        expect { token.jwt }.to raise_error(JWT::EncodeError)
      end
    end
  end
end
