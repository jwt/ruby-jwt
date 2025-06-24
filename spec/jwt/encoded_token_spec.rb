# frozen_string_literal: true

RSpec.describe JWT::EncodedToken do
  let(:payload) { { 'pay' => 'load' } }
  let(:header) { {} }
  let(:encoded_token) { JWT::Token.new(payload: payload, header: header).tap { |t| t.sign!(algorithm: 'HS256', key: 'secret') }.jwt }
  let(:detached_payload_token) do
    JWT::Token.new(payload: payload).tap do |t|
      t.detach_payload!
      t.sign!(algorithm: 'HS256', key: 'secret')
    end
  end

  subject(:token) { described_class.new(encoded_token) }

  describe '#unverified_payload' do
    it { expect(token.unverified_payload).to eq(payload) }

    context 'when payload is detached' do
      let(:encoded_token) { detached_payload_token.jwt }

      context 'when payload provided in separate' do
        before { token.encoded_payload = detached_payload_token.encoded_payload }
        it { expect(token.unverified_payload).to eq(payload) }
      end

      context 'when payload is not provided' do
        it 'raises decode error' do
          expect { token.unverified_payload }.to raise_error(JWT::DecodeError, 'Encoded payload is empty')
        end
      end
    end

    context 'when payload is not encoded and the b64 crit is enabled' do
      subject(:token) { described_class.new(encoded_token) }
      let(:encoded_token) { 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature' }
      before { token.encoded_payload = '{"foo": "bar"}' }

      it 'handles the payload encoding' do
        expect(token.unverified_payload).to eq({ 'foo' => 'bar' })
      end
    end

    context 'when token is the empty string' do
      let(:encoded_token) { '' }

      it 'raises decode error' do
        expect { token.unverified_payload }.to raise_error(JWT::DecodeError, 'Invalid segment encoding')
      end
    end
  end

  describe '#payload' do
    context 'when token is verified using #valid?' do
      before do
        token.valid?(signature: { algorithm: 'HS256', key: 'secret' })
      end

      it { expect(token.payload).to eq(payload) }
    end

    context 'when token is verified using #verify_signature! and #verify_claims!' do
      before do
        token.verify_signature!(algorithm: 'HS256', key: 'secret')
        token.verify_claims!
      end

      it { expect(token.payload).to eq(payload) }
    end

    context 'when token is checked using #valid_signature? and #valid_claims?' do
      before do
        token.valid_signature?(algorithm: 'HS256', key: 'secret')
        token.valid_claims?
      end

      it { expect(token.payload).to eq(payload) }
    end

    context 'when token is verified using #verify_signature!' do
      before { token.verify_signature!(algorithm: 'HS256', key: 'secret') }

      it 'raises an error' do
        expect { token.payload }.to raise_error(JWT::DecodeError, 'Verify the token claims before accessing the payload')
      end
    end

    context 'when token is verified using #valid_signature? but is not valid' do
      before { token.valid_signature?(algorithm: 'HS256', key: 'wrong') }

      it 'raises an error' do
        expect { token.payload }.to raise_error(JWT::DecodeError, 'Verify the token signature before accessing the payload')
      end
    end

    context 'when token is not verified' do
      it 'raises an error' do
        expect { token.payload }.to raise_error(JWT::DecodeError, 'Verify the token signature before accessing the payload')
      end
    end
  end

  describe '#header' do
    it { expect(token.header).to eq({ 'alg' => 'HS256' }) }

    context 'when token is the empty string' do
      let(:encoded_token) { '' }

      it 'raises decode error' do
        expect { token.header }.to raise_error(JWT::DecodeError, 'Invalid segment encoding')
      end
    end
  end

  describe '#signature' do
    it { expect(token.signature).to be_a(String) }
  end

  describe '#signing_input' do
    it { expect(token.signing_input).to eq('eyJhbGciOiJIUzI1NiJ9.eyJwYXkiOiJsb2FkIn0') }
  end

  describe '#verify_signature!' do
    context 'when key is valid' do
      it 'does not raise' do
        expect(token.verify_signature!(algorithm: 'HS256', key: 'secret')).to eq(nil)
      end
    end

    context 'when key is invalid' do
      it 'raises an error' do
        expect { token.verify_signature!(algorithm: 'HS256', key: 'wrong') }.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end
    end

    context 'when key is an array with one valid entry' do
      it 'does not raise' do
        expect(token.verify_signature!(algorithm: 'HS256', key: %w[wrong secret])).to eq(nil)
      end
    end

    context 'when algorithm is an empty array' do
      it 'raises an error' do
        expect { token.verify_signature!(key: 'secret', algorithm: []) }.to raise_error(JWT::VerificationError, 'No algorithm provided')
      end
    end

    context 'when algorithm is not given' do
      it 'raises an error' do
        expect { token.verify_signature!(key: 'secret') }.to raise_error(ArgumentError, /missing keyword/)
      end
    end

    context 'when header has invalid alg value' do
      let(:header) { { 'alg' => 'HS123' } }

      it 'does not raise' do
        expect(token.header).to eq(header)
        expect(token.verify_signature!(algorithm: 'HS256', key: 'secret')).to eq(nil)
      end
    end

    context 'when payload is detached' do
      let(:encoded_token) { detached_payload_token.jwt }

      context 'when payload provided in separate' do
        before { token.encoded_payload = detached_payload_token.encoded_payload }
        it 'does not raise' do
          expect(token.verify_signature!(algorithm: 'HS256', key: 'secret')).to eq(nil)
        end
      end

      context 'when payload is not provided' do
        it 'raises VerificationError' do
          expect { token.verify_signature!(algorithm: 'HS256', key: 'secret') }.to raise_error(JWT::VerificationError, 'Signature verification failed')
        end
      end
    end

    context 'when key_finder is given' do
      it 'uses key provided by keyfinder' do
        expect(token.verify_signature!(algorithm: 'HS256', key_finder: ->(_token) { 'secret' })).to eq(nil)
      end

      it 'can utilize an array provided by keyfinder' do
        expect(token.verify_signature!(algorithm: 'HS256', key_finder: ->(_token) { %w[wrong secret] })).to eq(nil)
      end
    end

    context 'when neither key or key_finder is given' do
      it 'raises an ArgumentError' do
        expect { token.verify_signature!(algorithm: 'HS256') }.to raise_error(ArgumentError, 'Provide either key or key_finder, not both or neither')
      end
    end

    context 'when both key or key_finder is given' do
      it 'raises an ArgumentError' do
        expect { token.verify_signature!(algorithm: 'HS256', key: 'key', key_finder: 'finder') }.to raise_error(ArgumentError, 'Provide either key or key_finder, not both or neither')
      end
    end

    context 'when payload is not encoded' do
      let(:encoded_token) { 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY' }
      before { token.encoded_payload = '$.02' }

      let(:key) { Base64.urlsafe_decode64('AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow') }

      it 'does not raise' do
        expect(token.verify_signature!(algorithm: 'HS256', key: key)).to eq(nil)
      end
    end

    context 'when JWT::KeyFinder is used as a key_finder' do
      let(:jwk) { JWT::JWK.new(test_pkey('rsa-2048-private.pem')) }
      let(:encoded_token) do
        JWT::Token.new(payload: payload, header: { kid: jwk.kid })
                  .tap { |t| t.sign!(algorithm: 'RS256', key: jwk.signing_key) }
                  .jwt
      end

      it 'uses the keys provided by the JWK key finder' do
        key_finder = JWT::JWK::KeyFinder.new(jwks: JWT::JWK::Set.new(jwk))
        expect(token.verify_signature!(algorithm: 'RS256', key_finder: key_finder)).to eq(nil)
      end
    end

    context 'when JWK is given as a key' do
      let(:jwk) { JWT::JWK.new(test_pkey('rsa-2048-private.pem'), alg: 'RS256') }
      let(:encoded_token) do
        JWT::Token.new(payload: payload)
                  .tap { |t| t.sign!(algorithm: 'RS256', key: jwk.signing_key) }
                  .jwt
      end

      context 'with empty algorithm array provided' do
        it 'uses the JWK for verification' do
          expect(token.verify_signature!(key: jwk, algorithm: [])).to eq(nil)
        end
      end

      context 'with algorithms supported by key provided' do
        it 'uses the JWK for verification' do
          expect(token.verify_signature!(algorithm: %w[RS256 RS512], key: jwk)).to eq(nil)
        end
      end

      context 'with algorithms not supported by key provided' do
        it 'raises JWT::VerificationError' do
          expect { token.verify_signature!(algorithm: %w[RS384 RS512], key: jwk) }.to raise_error(JWT::VerificationError, 'Provided JWKs do not support one of the specified algorithms: RS384, RS512')
        end
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

      context 'when no claims are provided' do
        it 'raises ExpiredSignature error' do
          expect { token.verify_claims! }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
      end

      context 'when claim validation skips verifying the exp claim' do
        it 'does not raise' do
          expect { token.verify_claims!({}) }.not_to raise_error
        end
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

      context 'when payload is detached' do
        let(:encoded_token) { detached_payload_token.jwt }
        context 'when payload provided in separate' do
          before { token.encoded_payload = detached_payload_token.encoded_payload }
          it 'raises claim verification error' do
            expect { token.verify_claims!(:exp, :nbf) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
          end
        end
        context 'when payload is not provided' do
          it 'raises decode error' do
            expect { token.verify_claims!(:exp, :nbf) }.to raise_error(JWT::DecodeError, 'Encoded payload is empty')
          end
        end
      end
    end

    context 'when header contains crits header' do
      let(:header) { { crit: ['b64'] } }

      context 'when expected crits are missing' do
        it 'raises an error' do
          expect { token.verify_claims!(crit: ['other']) }.to raise_error(JWT::InvalidCritError, 'Crit header missing expected values: other')
        end
      end

      context 'when expected crits are present' do
        it 'passes verification' do
          expect { token.verify_claims!(crit: ['b64']) }.not_to raise_error
        end
      end
    end
  end

  context '#verify!' do
    context 'when key is valid' do
      it 'does not raise' do
        expect(token.verify!(signature: { algorithm: 'HS256', key: 'secret' })).to eq(nil)
      end
    end

    context 'when key is invalid' do
      it 'raises an error' do
        expect { token.verify!(signature: { algorithm: 'HS256', key: 'wrong' }) }.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end
    end

    context 'when claims are invalid' do
      let(:payload) { { 'pay' => 'load', exp: Time.now.to_i - 1000 } }

      it 'raises an error' do
        expect do
          token.verify!(signature: { algorithm: 'HS256', key: 'secret' },
                        claims: { exp: { leeway: 900 } })
        end.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
      end
    end
  end

  context '#valid?' do
    context 'when key is valid' do
      it 'returns true' do
        expect(token.valid?(signature: { algorithm: 'HS256', key: 'secret' })).to be(true)
      end
    end

    context 'when key is invalid' do
      it 'returns false' do
        expect(token.valid?(signature: { algorithm: 'HS256', key: 'wrong' })).to be(false)
      end
    end

    context 'when claims are provided as an array' do
      it 'returns true' do
        expect(
          token.valid?(signature: { algorithm: 'HS256', key: 'secret' }, claims: [:exp])
        ).to be(true)
      end
    end

    context 'when claims are invalid' do
      let(:payload) { { 'pay' => 'load', exp: Time.now.to_i - 1000 } }

      it 'returns false' do
        expect(
          token.valid?(signature: { algorithm: 'HS256', key: 'secret' },
                       claims: { exp: { leeway: 900 } })
        ).to be(false)
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

      context 'when no claims are provided' do
        it 'validates the exp claim and returns false' do
          expect(token.valid_claims?).to be(false)
        end
      end

      context 'when claim validation skips verifying the exp claim' do
        it 'returns true' do
          expect(token.valid_claims?({})).to be(true)
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

  describe 'integration use-cases' do
    context 'simple verify HS256 with defaults' do
      let(:encoded_token) do
        JWT::Token.new(payload: { 'pay' => 'load' })
                  .tap { |t| t.sign!(algorithm: 'HS256', key: 'secret_signing_key') }
                  .jwt
      end

      it 'protects the user from unverified payload access' do
        token = described_class.new(encoded_token)

        expect(token.unverified_payload).to eq({ 'pay' => 'load' })
        expect(token.header).to eq({ 'alg' => 'HS256' })

        expect { token.payload }.to raise_error(JWT::DecodeError, 'Verify the token signature before accessing the payload')

        expect(token.valid_signature?(algorithm: 'HS256', key: 'invalid_signing_key')).to be(false)
        expect { token.payload }.to raise_error(JWT::DecodeError, 'Verify the token signature before accessing the payload')

        expect(token.valid_signature?(algorithm: 'HS256', key: 'secret_signing_key')).to be(true)
        expect { token.payload }.to raise_error(JWT::DecodeError, 'Verify the token claims before accessing the payload')

        expect(token.valid_claims?(iss: 'issuer')).to be(false)
        expect { token.payload }.to raise_error(JWT::DecodeError, 'Verify the token claims before accessing the payload')

        expect(token.valid_claims?).to be(true)
        expect(token.payload).to eq({ 'pay' => 'load' })

        token = described_class.new(encoded_token)

        expect(token.valid?(signature: { algorithm: 'HS256', key: 'invalid_signing_key' })).to be(false)
        expect { token.payload }.to raise_error(JWT::DecodeError, 'Verify the token signature before accessing the payload')

        expect(token.valid?(signature: { algorithm: 'HS256', key: 'secret_signing_key' })).to be(true)
        expect(token.payload).to eq({ 'pay' => 'load' })
      end
    end
  end
end
