# frozen_string_literal: true

RSpec.describe JWT::JWK::KeyFinder do
  let(:jwk) { JWT::JWK.new('a-secret-for-HMAC') }
  let(:metadata) { {} }
  let(:parameters) { jwk.export(include_private: true).merge(metadata) }
  let(:finder) { described_class.new(jwks: { keys: [parameters] }) }

  describe '#key_for' do
    it 'preserves lookup without an algorithm' do
      expect(finder.key_for(jwk.kid)).to eq(jwk.verify_key)
    end

    it 'preserves lookup by an explicit key field' do
      parameters[:x5t] = 'thumbprint'
      expect(finder.key_for('thumbprint', :x5t)).to eq(jwk.verify_key)
    end

    it 'checks the algorithm when supplied' do
      parameters[:alg] = 'HS512'
      expect { finder.key_for(jwk.kid, algorithm: 'HS256') }.to raise_error(JWT::VerificationKeyError)
    end

    it 'checks key usage even without an algorithm' do
      parameters[:use] = 'enc'
      expect { finder.key_for(jwk.kid) }.to raise_error(JWT::VerificationKeyError)
    end
  end

  [
    ['HS256', 'HS512', nil],
    ['RS512', 'RS256', 'rsa-2048-private.pem'],
    ['PS256', 'PS512', 'rsa-2048-private.pem'],
    ['ES256', 'ES384', 'ec256-private.pem']
  ].each do |algorithm, other_algorithm, key_file|
    context "when verifying #{algorithm}" do
      let(:jwk) { JWT::JWK.new(key_file ? test_pkey(key_file) : 'a-secret-for-HMAC') }
      let(:parameters) { jwk.export(include_private: key_file.nil?).merge(metadata) }
      let(:payload) { { 'data' => 'signed payload' } }
      let(:headers) { { kid: jwk.kid } }
      let(:jwt) { JWT.encode(payload, jwk.signing_key, algorithm, headers) }
      let(:token) { JWT::EncodedToken.new(jwt) }
      let(:algorithms) { [algorithm, other_algorithm] }

      [{}, { alg: algorithm }, { use: 'sig' }, { key_ops: ['verify'] },
       { alg: algorithm, use: 'sig', key_ops: %w[sign verify] }].each do |metadata|
        context "with compatible metadata #{metadata.inspect}" do
          let(:metadata) { metadata }

          it 'decodes through the jwks option' do
            expect(JWT.decode(jwt, nil, true, algorithms: algorithms, jwks: { keys: [parameters] }).first).to eq(payload)
          end

          it 'verifies through the token key finder' do
            expect(token.verify_signature!(algorithm: algorithms, key_finder: finder)).to be_nil
          end
        end
      end

      [{ alg: other_algorithm }, { alg: algorithm.downcase }, { use: 'enc' }, { key_ops: ['encrypt'] },
       { key_ops: ['sign'] }, { key_ops: [] },
       { use: 'enc', key_ops: ['verify'] }, { use: 'sig', key_ops: ['encrypt'] }].each do |metadata|
        context "with incompatible metadata #{metadata.inspect}" do
          let(:metadata) { metadata }

          it 'rejects decoding through the jwks option' do
            expect { JWT.decode(jwt, nil, true, algorithms: algorithms, jwks: { keys: [parameters] }) }.to raise_error(JWT::VerificationKeyError)
          end

          it 'rejects verification through the token key finder' do
            expect { token.verify_signature!(algorithm: algorithms, key_finder: finder) }.to raise_error(JWT::VerificationKeyError)
          end
        end
      end
    end
  end

  context 'when looking up a token without a kid' do
    let(:metadata) { { alg: 'HS512' } }
    let(:finder) { described_class.new(jwks: { keys: [parameters] }, allow_nil_kid: true) }
    let(:token) { JWT::EncodedToken.new(JWT.encode({}, jwk.signing_key, 'HS256')) }

    it 'still enforces the JWK algorithm' do
      expect { finder.call(token) }.to raise_error(JWT::VerificationKeyError)
    end
  end

  context 'when looking up JSON keys by x5t' do
    let(:metadata) { { alg: 'HS512', x5t: 'thumbprint' } }
    let(:finder) { described_class.new(jwks: JSON.parse(JSON.generate(keys: [parameters])), key_fields: [:x5t]) }
    let(:token) { JWT::EncodedToken.new(JWT.encode({}, jwk.signing_key, 'HS256', x5t: 'thumbprint')) }

    it 'still enforces the JWK algorithm' do
      expect { finder.call(token) }.to raise_error(JWT::VerificationKeyError)
    end
  end
end
