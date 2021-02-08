# frozen_string_literal: true

require_relative '../spec_helper'
require 'jwt'

describe JWT do
  shared_context 'decode a signed token' do
    let(:jwk)           { JWT::JWK.new(keypair) }
    let(:public_jwks) { { keys: [exported_jwk, { kid: 'not_the_correct_one' }] } }
    let(:token_payload) { {'data' => 'something'} }
    let(:token_headers) { { kid: jwk.kid } }
    let(:signed_token)  { described_class.encode(token_payload, jwk.signing_key, algorithm, token_headers) }

    context 'when JWK features are used manually' do
      it 'is able to decode the token' do
        payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm] }) do |header, _payload|
          JWT::JWK.import(public_jwks[:keys].find { |key| key[:kid] == header['kid'] }).verify_key
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
        key_loader = ->(options) { JSON.parse(JSON.generate(public_jwks)) }
        payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: key_loader})
        expect(payload).to eq(token_payload)
      end
    end
  end

  describe '.decode for JWK usecase' do
    context 'public RSA' do
      let(:keypair)       { OpenSSL::PKey::RSA.new(2048) }
      let(:algorithm)     { 'RS512' }
      let(:exported_jwk)  { jwk.export }

      include_context 'decode a signed token'
    end

    context 'private RSA' do
      let(:keypair)       { OpenSSL::PKey::RSA.new(2048) }
      let(:algorithm)     { 'RS512' }
      let(:exported_jwk)  { jwk.export(include_private: true) }

      include_context 'decode a signed token'
    end

    context 'EC' do
      let(:keypair)       { OpenSSL::PKey::EC.new('secp384r1').generate_key }
      let(:algorithm)     { 'ES384' }
      let(:exported_jwk)  { jwk.export }

      include_context 'decode a signed token'
    end

    context 'HMAC' do
      let(:keypair)       { 'secret_word' }
      let(:algorithm)     { 'HS256' }
      let(:exported_jwk)  { jwk.export(include_private: true) }

      include_context 'decode a signed token'
    end
  end
end
