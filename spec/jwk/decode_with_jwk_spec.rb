# frozen_string_literal: true

describe JWT do
  describe '.decode for JWK usecase' do
    let(:keypair)       { OpenSSL::PKey::RSA.new(2048) }
    let(:jwk)           { JWT::JWK.new(keypair) }
    let(:public_jwks) { { keys: [jwk.export, { kid: 'not_the_correct_one' }] } }
    let(:token_payload) { {'data' => 'something'} }
    let(:token_headers) { { kid: jwk.kid } }
    let(:algorithm)     { 'RS512' }
    let(:signed_token)  { described_class.encode(token_payload, jwk.private_key, algorithm, token_headers) }

    context 'when JWK features are used manually' do
      it 'is able to decode the token' do
        payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm] }) do |header, _payload|
          JWT::JWK.import(public_jwks[:keys].find { |key| key[:kid] == header['kid'] }).keypair
        end
        expect(payload).to eq(token_payload)
      end
    end

    context 'when jwk keys are given as an array' do
      context 'and kid is in the set' do
        it 'is able to decode the token' do
          payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: public_jwks})
          expect(payload).to eq(token_payload)
        end
      end

      context 'and kid is not in the set' do
        before do
          public_jwks[:keys].first[:kid] = 'NOT_A_MATCH'
        end
        it 'raises an exception' do
          expect { described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: public_jwks}) }.to raise_error(
            JWT::DecodeError, /Could not find public key for kid .*/
          )
        end
      end

      context 'no keys are found in the set' do
        let(:public_jwks) { {keys: []} }
        it 'raises an exception' do
          expect { described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: public_jwks}) }.to raise_error(
            JWT::DecodeError, /No keys found in jwks/
          )
        end
      end

      context 'token does not know the kid' do
        let(:token_headers) { {} }
        it 'raises an exception' do
          expect { described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: public_jwks}) }.to raise_error(
            JWT::DecodeError, 'No key id (kid) found from token headers'
          )
        end
      end
    end

    context 'when jwk keys are loaded using a proc/lambda' do
      it 'decodes the token' do
        payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: lambda { |_opts| public_jwks }})
        expect(payload).to eq(token_payload)
      end
    end

    context 'when jwk keys are rotated' do
      it 'decodes the token' do
        key_loader = ->(options) { options[:invalidate] ? public_jwks : { keys: [] } }
        payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: key_loader})
        expect(payload).to eq(token_payload)
      end
    end

    context 'when jwk keys are loaded from JSON with string keys' do
      it 'decodes the token' do
        key_loader = ->(_options) { JSON.parse(JSON.generate(public_jwks)) }
        payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: key_loader})
        expect(payload).to eq(token_payload)
      end
    end

    context 'when OKP keys are used' do
      let(:keypair) { RbNaCl::Signatures::Ed25519::SigningKey.new(SecureRandom.hex) }
      let(:algorithm) { 'ED25519' }
      it 'decodes the token' do
        key_loader = ->(_options) { JSON.parse(JSON.generate(public_jwks)) }
        payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: key_loader})
        expect(payload).to eq(token_payload)
      end
    end if defined?(RbNaCl)
  end
end
