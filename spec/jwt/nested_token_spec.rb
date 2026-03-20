# frozen_string_literal: true

RSpec.describe JWT::NestedToken do
  let(:inner_secret) { 'inner_secret_key' }
  let(:outer_secret) { 'outer_secret_key' }
  let(:inner_payload) { { 'user_id' => 123, 'role' => 'admin' } }

  describe '#sign!' do
    subject(:nested_token) { described_class.new(inner_jwt) }

    context 'with HMAC algorithms' do
      let(:inner_jwt) { JWT.encode(inner_payload, inner_secret, 'HS256') }

      it 'creates a nested JWT with cty header set to JWT (NEST-01, NEST-02)' do
        nested_token.sign!(algorithm: 'HS256', key: outer_secret)

        outer_token = JWT::EncodedToken.new(nested_token.jwt)
        expect(outer_token.header['cty']).to eq('JWT')
        expect(outer_token.header['alg']).to eq('HS256')
      end

      it 'preserves the inner JWT as the payload bytes (NEST-01)' do
        nested_token.sign!(algorithm: 'HS256', key: outer_secret)

        encoded_payload = nested_token.jwt.split('.')[1]
        expect(JWT::Base64.url_decode(encoded_payload)).to eq(inner_jwt)
      end

      it 'allows traversal to the inner token after signing' do
        nested_token.sign!(algorithm: 'HS256', key: outer_secret)

        outer_token = JWT::EncodedToken.new(nested_token.jwt)
        expect(outer_token.inner_token.to_s).to eq(inner_jwt)
      end

      it 'allows additional header fields (NEST-02)' do
        nested_token.sign!(
          algorithm: 'HS256',
          key: outer_secret,
          header: { 'kid' => 'my-key-id' }
        )

        outer_token = JWT::EncodedToken.new(nested_token.jwt)
        expect(outer_token.header['kid']).to eq('my-key-id')
        expect(outer_token.header['cty']).to eq('JWT')
      end
    end

    context 'with RSA algorithm' do
      let(:rsa_private) { test_pkey('rsa-2048-private.pem') }
      let(:rsa_public) { rsa_private.public_key }
      let(:inner_jwt) { JWT.encode(inner_payload, inner_secret, 'HS256') }

      it 'creates a nested JWT signed with RSA' do
        nested_token.sign!(algorithm: 'RS256', key: rsa_private)

        outer_token = JWT::EncodedToken.new(nested_token.jwt)
        expect(outer_token.header['alg']).to eq('RS256')
        expect(outer_token.header['cty']).to eq('JWT')

        outer_token.verify_signature!(algorithm: 'RS256', key: rsa_public)
        expect(outer_token.inner_token.to_s).to eq(inner_jwt)
      end
    end
  end

  describe '#verify!' do
    let(:inner_jwt) { JWT.encode(inner_payload, inner_secret, 'HS256') }
    let(:nested_jwt) do
      described_class.new(inner_jwt).tap do |token|
        token.sign!(algorithm: 'HS256', key: outer_secret)
      end.jwt
    end

    it 'decodes a nested JWT and returns all levels (NEST-03)' do
      tokens = described_class.new(nested_jwt).verify!(
        keys: [
          { algorithm: 'HS256', key: outer_secret },
          { algorithm: 'HS256', key: inner_secret }
        ]
      )

      expect(tokens.length).to eq(2)
      expect(tokens.first.header['cty']).to eq('JWT')
      expect(tokens.last.payload).to eq(inner_payload)
    end

    it 'handles case-insensitive cty header values (NEST-04)' do
      signer = JWT::JWA.create_signer(algorithm: 'HS256', key: outer_secret)
      header = { 'cty' => 'jwt' }.merge(signer.jwa.header) { |_key, old, _new| old }
      encoded_header = JWT::Base64.url_encode(JWT::JSON.generate(header))
      encoded_payload = JWT::Base64.url_encode(inner_jwt)
      signature = signer.sign(data: [encoded_header, encoded_payload].join('.'))
      nested_jwt_lowercase = [encoded_header, encoded_payload, JWT::Base64.url_encode(signature)].join('.')

      tokens = described_class.new(nested_jwt_lowercase).verify!(
        keys: [
          { algorithm: 'HS256', key: outer_secret },
          { algorithm: 'HS256', key: inner_secret }
        ]
      )

      expect(tokens.length).to eq(2)
      expect(tokens.last.payload).to eq(inner_payload)
    end

    it 'supports multiple nesting levels (NEST-05)' do
      level_1_jwt = JWT.encode(inner_payload, 'secret_1', 'HS256')
      level2 = described_class.new(level_1_jwt)
      level2.sign!(algorithm: 'HS384', key: 'secret_2')
      level3 = described_class.new(level2.jwt)
      level3.sign!(algorithm: 'HS512', key: 'secret_3')

      tokens = described_class.new(level3.jwt).verify!(
        keys: [
          { algorithm: 'HS512', key: 'secret_3' },
          { algorithm: 'HS384', key: 'secret_2' },
          { algorithm: 'HS256', key: 'secret_1' }
        ]
      )

      expect(tokens.length).to eq(3)
      expect(tokens[0].header['alg']).to eq('HS512')
      expect(tokens[1].header['alg']).to eq('HS384')
      expect(tokens[2].header['alg']).to eq('HS256')
      expect(tokens.last.payload).to eq(inner_payload)
    end

    it 'verifies signatures and claims of the innermost token (NEST-06)' do
      tokens = described_class.new(nested_jwt).verify!(
        keys: [
          { algorithm: 'HS256', key: outer_secret },
          { algorithm: 'HS256', key: inner_secret }
        ]
      )

      expect { tokens.last.payload }.not_to raise_error
      expect(tokens.first.header['cty']).to eq('JWT')
    end

    it 'raises an error if outer signature verification fails (NEST-06)' do
      expect do
        described_class.new(nested_jwt).verify!(
          keys: [
            { algorithm: 'HS256', key: 'wrong_key' },
            { algorithm: 'HS256', key: inner_secret }
          ]
        )
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end

    it 'raises an error if inner signature verification fails (NEST-06)' do
      expect do
        described_class.new(nested_jwt).verify!(
          keys: [
            { algorithm: 'HS256', key: outer_secret },
            { algorithm: 'HS256', key: 'wrong_key' }
          ]
        )
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end

    it 'raises DecodeError when key count does not match nesting depth' do
      simple_jwt = JWT.encode(inner_payload, inner_secret, 'HS256')

      expect do
        described_class.new(simple_jwt).verify!(
          keys: [
            { algorithm: 'HS256', key: inner_secret },
            { algorithm: 'HS256', key: 'extra_key' }
          ]
        )
      end.to raise_error(JWT::DecodeError, 'Expected 1 key configurations, got 2')
    end

    context 'with different algorithms at each level' do
      let(:rsa_private) { test_pkey('rsa-2048-private.pem') }
      let(:rsa_public) { rsa_private.public_key }

      it 'supports HS256 inner with RS256 outer' do
        inner_jwt = JWT.encode(inner_payload, inner_secret, 'HS256')
        nested = described_class.new(inner_jwt)
        nested.sign!(algorithm: 'RS256', key: rsa_private)

        tokens = described_class.new(nested.jwt).verify!(
          keys: [
            { algorithm: 'RS256', key: rsa_public },
            { algorithm: 'HS256', key: inner_secret }
          ]
        )

        expect(tokens.length).to eq(2)
        expect(tokens.first.header['alg']).to eq('RS256')
        expect(tokens.last.header['alg']).to eq('HS256')
        expect(tokens.last.payload).to eq(inner_payload)
      end

      it 'supports RS256 inner with HS256 outer' do
        inner_jwt = JWT.encode(inner_payload, rsa_private, 'RS256')
        nested = described_class.new(inner_jwt)
        nested.sign!(algorithm: 'HS256', key: outer_secret)

        tokens = described_class.new(nested.jwt).verify!(
          keys: [
            { algorithm: 'HS256', key: outer_secret },
            { algorithm: 'RS256', key: rsa_public }
          ]
        )

        expect(tokens.length).to eq(2)
        expect(tokens.first.header['alg']).to eq('HS256')
        expect(tokens.last.header['alg']).to eq('RS256')
        expect(tokens.last.payload).to eq(inner_payload)
      end
    end
  end
end
