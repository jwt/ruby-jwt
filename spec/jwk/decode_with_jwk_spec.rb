# frozen_string_literal: true

RSpec.describe JWT do
  describe '.decode for JWK usecase' do
    let(:keypair)       { OpenSSL::PKey::RSA.new(2048) }
    let(:jwk)           { JWT::JWK.new(keypair) }
    let(:public_jwks) { { keys: [jwk.export, { kid: 'not_the_correct_one', kty: 'oct', k: 'secret' }] } }
    let(:token_payload) { { 'data' => 'something' } }
    let(:token_headers) { { kid: jwk.kid } }
    let(:algorithm)     { 'RS512' }
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
          payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: public_jwks })
          expect(payload).to eq(token_payload)
        end
      end

      context 'and kid is not in the set' do
        before do
          public_jwks[:keys].first[:kid] = 'NOT_A_MATCH'
        end
        it 'raises an exception' do
          expect { described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: public_jwks }) }.to raise_error(
            JWT::DecodeError, /Could not find public key for kid .*/
          )
        end
      end

      context 'no keys are found in the set' do
        let(:public_jwks) { { keys: [] } }
        it 'raises an exception' do
          expect { described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: public_jwks }) }.to raise_error(
            JWT::DecodeError, /No keys found in jwks/
          )
        end
      end

      context 'token does not know the kid' do
        let(:token_headers) { {} }
        it 'raises an exception' do
          expect { described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: public_jwks }) }.to raise_error(
            JWT::DecodeError, 'No key id (kid) found from token headers'
          )
        end
      end
    end

    context 'when jwk keys are loaded using a proc/lambda' do
      it 'decodes the token' do
        payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: lambda { |_opts| public_jwks } })
        expect(payload).to eq(token_payload)
      end
    end

    context 'when jwk keys are rotated' do
      it 'decodes the token' do
        key_loader = ->(options) { options[:invalidate] ? public_jwks : { keys: [] } }
        payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: key_loader })
        expect(payload).to eq(token_payload)
      end
    end

    context 'when jwk keys are loaded from JSON with string keys' do
      it 'decodes the token' do
        key_loader = ->(_options) { JSON.parse(JSON.generate(public_jwks)) }
        payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: key_loader })
        expect(payload).to eq(token_payload)
      end
    end

    context 'when the token kid is nil' do
      let(:token_headers) { {} }
      context 'and allow_nil_kid is specified' do
        it 'decodes the token' do
          key_loader = ->(_options) { JSON.parse(JSON.generate(public_jwks)) }
          payload, _header = described_class.decode(signed_token, nil, true, { algorithms: ['RS512'], jwks: key_loader, allow_nil_kid: true })
          expect(payload).to eq(token_payload)
        end
      end
    end

    context 'when the token kid is not a string' do
      let(:token_headers) { { kid: 5 } }
      it 'raises an exception' do
        expect { described_class.decode(signed_token, nil, true, { algorithms: ['RS512'], jwks: public_jwks }) }.to raise_error(
          JWT::DecodeError, 'Invalid type for kid header parameter'
        )
      end
    end

    context 'mixing algorithms using kid header' do
      let(:hmac_jwk)           { JWT::JWK.new('secret') }
      let(:rsa_jwk)            { JWT::JWK.new(OpenSSL::PKey::RSA.new(2048)) }
      let(:ec_jwk_secp384r1)   { JWT::JWK.new(OpenSSL::PKey::EC.generate('secp384r1')) }
      let(:ec_jwk_secp521r1)   { JWT::JWK.new(OpenSSL::PKey::EC.generate('secp521r1')) }
      let(:jwks)               { { keys: [hmac_jwk.export(include_private: true), rsa_jwk.export, ec_jwk_secp384r1.export, ec_jwk_secp521r1.export] } }

      context 'when RSA key is pointed to as HMAC secret' do
        let(:signed_token) { described_class.encode({ 'foo' => 'bar' }, 'is not really relevant in the scenario', 'HS256', { kid: rsa_jwk.kid }) }

        it 'raises JWT::DecodeError' do
          expect { described_class.decode(signed_token, nil, true, algorithms: ['HS256'], jwks: jwks) }.to raise_error(JWT::DecodeError, 'HMAC key expected to be a String')
        end
      end

      context 'when EC key is pointed to as HMAC secret' do
        let(:signed_token) { described_class.encode({ 'foo' => 'bar' }, 'is not really relevant in the scenario', 'HS256', { kid: ec_jwk_secp384r1.kid }) }

        it 'raises JWT::DecodeError' do
          expect { described_class.decode(signed_token, nil, true, algorithms: ['HS256'], jwks: jwks) }.to raise_error(JWT::DecodeError, 'HMAC key expected to be a String')
        end
      end

      context 'when EC key is pointed to as RSA public key' do
        let(:signed_token) { described_class.encode({ 'foo' => 'bar' }, rsa_jwk.signing_key, algorithm, { kid: ec_jwk_secp384r1.kid }) }

        it 'fails in some way' do
          expect { described_class.decode(signed_token, nil, true, algorithms: [algorithm], jwks: jwks) }.to(
            raise_error(JWT::VerificationError, 'Signature verification raised')
          )
        end
      end

      context 'when HMAC secret is pointed to as RSA public key' do
        let(:signed_token) { described_class.encode({ 'foo' => 'bar' }, rsa_jwk.signing_key, algorithm, { kid: hmac_jwk.kid }) }

        it 'fails in some way' do
          expect { described_class.decode(signed_token, nil, true, algorithms: [algorithm], jwks: jwks) }.to(
            raise_error(NoMethodError, /undefined method `verify' for/)
          )
        end
      end

      context 'when HMAC secret is pointed to as EC public key' do
        let(:signed_token) { described_class.encode({ 'foo' => 'bar' }, ec_jwk_secp384r1.signing_key, 'ES384', { kid: hmac_jwk.kid }) }

        it 'fails in some way' do
          expect { described_class.decode(signed_token, nil, true, algorithms: ['ES384'], jwks: jwks) }.to(
            raise_error(NoMethodError, /undefined method `group' for/)
          )
        end
      end

      context 'when ES384 key is pointed to as ES512 key' do
        let(:signed_token) { described_class.encode({ 'foo' => 'bar' }, ec_jwk_secp384r1.signing_key, 'ES512', { kid: ec_jwk_secp521r1.kid }) }

        it 'fails in some way' do
          expect { described_class.decode(signed_token, nil, true, algorithms: ['ES512'], jwks: jwks) }.to(
            raise_error(JWT::IncorrectAlgorithm, 'payload algorithm is ES512 but ES384 signing key was provided')
          )
        end
      end

      if defined?(RbNaCl)
        context 'when OKP keys are used' do
          before do
            skip('Requires the rbnacl gem') unless JWT.rbnacl?
          end

          let(:keypair) { RbNaCl::Signatures::Ed25519::SigningKey.new(SecureRandom.hex) }
          let(:algorithm) { 'ED25519' }

          it 'decodes the token' do
            key_loader = ->(_options) { JSON.parse(JSON.generate(public_jwks)) }
            payload, _header = described_class.decode(signed_token, nil, true, { algorithms: [algorithm], jwks: key_loader })
            expect(payload).to eq(token_payload)
          end
        end
      end
    end
  end
end
