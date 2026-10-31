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

    it 'preserves raw-key lookup with algorithm metadata' do
      parameters[:alg] = 'HS256'
      expect(finder.key_for(jwk.kid)).to eq(jwk.verify_key)
    end

    it 'checks key usage even without an algorithm' do
      parameters[:use] = 'enc'
      expect { finder.key_for(jwk.kid) }.to raise_error(JWT::SignatureError)
    end
  end

  [
    ['HS256', 'HS512', nil],
    ['RS512', 'RS256', 'rsa-2048-private.pem'],
    ['PS256', 'PS512', 'rsa-2048-private.pem'],
    ['ES256', 'ES384', 'ec256-private.pem']
  ].each do |algorithm, other_algorithm, key_file|
    context "when verifying #{algorithm}" do
      before do
        skip 'OpenSSL gem missing RSA-PSS support' if algorithm.start_with?('PS') && !OpenSSL::PKey::RSA.method_defined?(:sign_pss)
      end

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
            expect { JWT.decode(jwt, nil, true, algorithms: algorithms, jwks: { keys: [parameters] }) }.to raise_error(JWT::SignatureError)
          end

          it 'rejects verification through the token key finder' do
            expect { token.verify_signature!(algorithm: algorithms, key_finder: finder) }.to raise_error(JWT::SignatureError)
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
      expect { finder.call(token) }.to raise_error(JWT::SignatureError)
    end
  end

  context 'when looking up JSON keys by x5t' do
    let(:metadata) { { alg: 'HS512', x5t: 'thumbprint' } }
    let(:finder) { described_class.new(jwks: JSON.parse(JSON.generate(keys: [parameters])), key_fields: [:x5t]) }
    let(:token) { JWT::EncodedToken.new(JWT.encode({}, jwk.signing_key, 'HS256', x5t: 'thumbprint')) }

    it 'still enforces the JWK algorithm' do
      expect { finder.call(token) }.to raise_error(JWT::SignatureError)
    end
  end

  context 'when the signature uses a different allowed algorithm from the metadata' do
    let(:metadata) { { alg: 'HS512' } }
    let(:jwt) do
      header = JWT::Base64.url_encode(JSON.generate(alg: 'HS512', kid: jwk.kid))
      payload = JWT::Base64.url_encode(JSON.generate(data: 'example'))
      input = [header, payload].join('.')
      signature = OpenSSL::HMAC.digest('SHA256', jwk.signing_key, input)
      [input, JWT::Base64.url_encode(signature)].join('.')
    end

    it 'rejects the signature despite matching JWK and token alg headers' do
      token = JWT::EncodedToken.new(jwt)
      expect { token.verify_signature!(algorithm: %w[HS256 HS512], key_finder: finder) }.to raise_error(JWT::VerificationError)
    end

    it 'also rejects decoding through the jwks option' do
      expect { JWT.decode(jwt, nil, true, algorithms: %w[HS256 HS512], jwks: { keys: [parameters] }) }.to raise_error(JWT::VerificationError)
    end
  end

  context 'when several keys match the identifier' do
    let(:metadata) { { alg: 'HS256', use: 'sig', key_ops: ['verify'] } }
    let(:jwt) { JWT.encode({ 'data' => 'example' }, jwk.signing_key, 'HS256', kid: jwk.kid) }
    let(:finder) { described_class.new(jwks: { keys: [incompatible_key, parameters] }) }

    [{ use: 'enc' }, { key_ops: ['sign'] }, { alg: 'HS512' }].each do |restrictions|
      context "with an incompatible first key #{restrictions.inspect}" do
        let(:incompatible_key) { JWT::JWK.new('a-different-secret', kid: jwk.kid).export(include_private: true).merge(restrictions) }

        it 'verifies with the compatible candidate' do
          expect(JWT::EncodedToken.new(jwt).verify_signature!(algorithm: %w[HS256 HS512], key_finder: finder)).to be_nil
          expect(JWT.decode(jwt, nil, true, algorithms: %w[HS256 HS512], jwks: { keys: [incompatible_key, parameters] }).first).to eq('data' => 'example')
        end
      end
    end

    context 'without a kid' do
      let(:incompatible_key) { JWT::JWK.new('a-different-secret', use: 'enc').export(include_private: true) }
      let(:jwt) { JWT.encode({ 'data' => 'example' }, jwk.signing_key, 'HS256') }

      it 'skips incompatible candidates with allow_nil_kid' do
        payload, = JWT.decode(jwt, nil, true, algorithms: ['HS256'], jwks: { keys: [incompatible_key, parameters] }, allow_nil_kid: true)
        expect(payload).to eq('data' => 'example')
      end
    end
  end

  context 'when cached metadata does not permit verification' do
    let(:metadata) { { use: 'sig' } }

    it 'uses the existing loader invalidation path to find an eligible key' do
      loader = ->(options) { { keys: [options[:invalidate] ? parameters : parameters.merge(use: 'enc')] } }
      jwt = JWT.encode({ 'data' => 'example' }, jwk.signing_key, 'HS256', kid: jwk.kid)
      expect(JWT.decode(jwt, nil, true, algorithms: ['HS256'], jwks: loader).first).to eq('data' => 'example')
    end
  end

  context 'when a restricted JWK is used directly' do
    [{ use: 'enc' }, { key_ops: ['sign'] }].each do |restrictions|
      it "rejects #{restrictions.inspect} without a key finder" do
        key = JWT::JWK.new(jwk.signing_key, restrictions.merge(alg: 'HS256'))
        token = JWT::EncodedToken.new(JWT.encode({}, jwk.signing_key, 'HS256'))
        expect { token.verify_signature!(algorithm: ['HS256'], key: key) }.to raise_error(JWT::VerificationKeyError)
      end
    end
  end
end
