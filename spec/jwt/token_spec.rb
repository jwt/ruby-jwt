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

    context 'when JWK is given as key' do
      let(:jwk) { JWT::JWK::RSA.new(OpenSSL::PKey::RSA.new(2048), alg: 'RS256') }

      it 'signs the token' do
        token.sign!(key: jwk)

        expect(JWT::EncodedToken.new(token.jwt).valid_signature?(algorithm: 'RS256', key: jwk.verify_key)).to be(true)
      end
    end

    context 'when string key is given but not algorithm' do
      it 'raises an error' do
        expect { token.sign!(key: 'secret') }.to raise_error(ArgumentError, 'Algorithm must be provided')
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

    context 'when alg is given in header' do
      let(:header) { { 'alg' => 'HS123' } }

      before do
        token.sign!(algorithm: 'HS256', key: 'secret')
      end

      it 'returns a signed and encoded token' do
        expect(JWT::EncodedToken.new(token.jwt).header).to eq({ 'alg' => 'HS123' })
      end
    end
  end

  describe '#detach_payload!' do
    context 'before token is signed' do
      it 'detaches the payload' do
        token.detach_payload!
        token.sign!(algorithm: 'HS256', key: 'secret')
        expect(token.jwt).to eq('eyJhbGciOiJIUzI1NiJ9..UEhDY1Qlj29ammxuVRA_-gBah4qTy5FngIWg0yEAlC0')
      end
    end
  end

  describe '#verify_claims!' do
    context 'when required_claims is passed' do
      it 'raises error' do
        expect { token.verify_claims!(required: ['exp']) }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim exp')
      end
    end
  end

  describe '#valid_claims?' do
    context 'exp claim' do
      let(:payload) { { 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

      context 'when claim is valid' do
        it 'returns true' do
          expect(token.valid_claims?(exp: { leeway: 1000 })).to be(true)
        end
      end

      context 'when claim is invalid' do
        it 'returns true' do
          expect(token.valid_claims?(:exp)).to be(false)
        end
      end
    end
  end

  describe '#claim_errors' do
    context 'exp claim' do
      let(:payload) { { 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

      context 'when claim is valid' do
        it 'returns empty array' do
          expect(token.claim_errors(exp: { leeway: 1000 })).to be_empty
        end
      end

      context 'when claim is invalid' do
        it 'returns array with error objects' do
          expect(token.claim_errors(:exp).map(&:message)).to eq(['Signature has expired'])
        end
      end
    end
  end
end
