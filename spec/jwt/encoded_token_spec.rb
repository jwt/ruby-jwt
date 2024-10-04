# frozen_string_literal: true

RSpec.describe JWT::EncodedToken do
  let(:payload) { { 'pay' => 'load' } }
  let(:encoded_token) { JWT.encode(payload, 'secret', 'HS256') }

  subject(:token) { described_class.new(encoded_token) }

  describe '#payload' do
    it { expect(token.payload).to eq(payload) }
  end

  describe '#header' do
    it { expect(token.header).to eq({ 'alg' => 'HS256' }) }
  end

  describe '#signature' do
    it { expect(token.signature).to be_a(String) }
  end

  describe '#signing_input' do
    it { expect(token.signing_input).to eq('eyJhbGciOiJIUzI1NiJ9.eyJwYXkiOiJsb2FkIn0') }
  end

  describe '#verify_signature!' do
    context 'when key is valid' do
      it 'returns nil' do
        expect(token.verify_signature!(algorithm: 'HS256', key: 'secret')).to eq(nil)
      end
    end

    context 'when key is invalid' do
      it 'raises an error' do
        expect { token.verify_signature!(algorithm: 'HS256', key: 'wrong') }.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end
    end
  end

  describe '#verify_claims!' do
    context 'when required_claims is passed' do
      it 'raises error' do
        expect { token.verify_claims!(required: ['exp']) }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim exp')
      end
    end

    context 'exp claim' do
      let(:payload) { { 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

      it 'verifies the exp' do
        token.verify_claims!(required: ['exp'])
        expect { token.verify_claims!(exp: {}) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        token.verify_claims!(exp: { leeway: 1000 })
      end

      context 'when claims given as symbol' do
        it 'validates the claim' do
          expect { token.verify_claims!(:exp) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
      end

      context 'when claims given as a list of symbols' do
        it 'validates the claim' do
          expect { token.verify_claims!(:exp, :nbf) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
      end

      context 'when claims given as a list of symbols and hashes' do
        it 'validates the claim' do
          expect { token.verify_claims!({ exp: { leeway: 1000 }, nbf: {} }, :exp, :nbf) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
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
