# frozen_string_literal: true

RSpec.describe 'Nested JWT Integration' do
  def create_nested_jwt(inner_jwt, algorithm:, key:, header: nil)
    JWT::NestedToken.new(inner_jwt).tap do |nested|
      if header
        nested.sign!(algorithm: algorithm, key: key, header: header)
      else
        nested.sign!(algorithm: algorithm, key: key)
      end
    end.jwt
  end

  describe 'RFC 7519 Compliance' do
    describe 'Section 5.2 "cty" Header Parameter' do
      it 'MUST be present for Nested JWTs' do
        inner_jwt = JWT.encode({ sub: 'user' }, 'secret', 'HS256')
        nested_jwt = create_nested_jwt(inner_jwt, algorithm: 'HS256', key: 'outer')

        token = JWT::EncodedToken.new(nested_jwt)
        expect(token.header).to have_key('cty')
      end

      it 'value MUST be "JWT"' do
        inner_jwt = JWT.encode({ sub: 'user' }, 'secret', 'HS256')
        nested_jwt = create_nested_jwt(inner_jwt, algorithm: 'HS256', key: 'outer')

        token = JWT::EncodedToken.new(nested_jwt)
        expect(token.header['cty']).to eq('JWT')
      end
    end

    describe 'Section 7.2 Validating a JWT - Step 8' do
      it 'handles cty="JWT" by identifying as nested' do
        inner_jwt = JWT.encode({ sub: 'user' }, 'secret', 'HS256')
        nested_jwt = create_nested_jwt(inner_jwt, algorithm: 'HS256', key: 'outer')

        token = JWT::EncodedToken.new(nested_jwt)
        expect(token.nested?).to be(true)
      end

      it 'handles cty="jwt" (lowercase) by identifying as nested' do
        inner_jwt = JWT.encode({ sub: 'user' }, 'secret', 'HS256')

        token = JWT::Token.new(payload: inner_jwt, header: { 'cty' => 'jwt' })
        token.sign!(algorithm: 'HS256', key: 'outer')

        encoded = JWT::EncodedToken.new(token.jwt)
        expect(encoded.nested?).to be(true)
      end

      it 'does not identify non-nested tokens as nested' do
        simple_jwt = JWT.encode({ sub: 'user' }, 'secret', 'HS256')

        token = JWT::EncodedToken.new(simple_jwt)
        expect(token.nested?).to be(false)
      end
    end
  end

  describe 'JWT::NestedToken instance API' do
    it 'creates a nested token with cty header' do
      inner = JWT.encode({ sub: 'user' }, 'secret', 'HS256')

      nested = JWT::NestedToken.new(inner)
      nested.sign!(algorithm: 'HS256', key: 'outer_secret')

      outer = JWT::EncodedToken.new(nested.jwt)
      expect(outer.header['cty']).to eq('JWT')
      expect(outer.inner_token.to_s).to eq(inner)
    end

    it 'allows additional headers' do
      inner = JWT.encode({ sub: 'user' }, 'secret', 'HS256')

      nested = JWT::NestedToken.new(inner)
      nested.sign!(algorithm: 'HS256', key: 'outer_secret', header: { 'kid' => 'key-1' })

      outer = JWT::EncodedToken.new(nested.jwt)
      expect(outer.header['cty']).to eq('JWT')
      expect(outer.header['kid']).to eq('key-1')
    end
  end

  describe 'JWT::EncodedToken nested methods' do
    let(:inner_payload) { { 'user_id' => 123 } }
    let(:inner_jwt) { JWT.encode(inner_payload, 'inner_secret', 'HS256') }
    let(:nested_jwt) { create_nested_jwt(inner_jwt, algorithm: 'HS256', key: 'outer_secret') }

    describe '#nested?' do
      it 'returns true for nested JWTs' do
        token = JWT::EncodedToken.new(nested_jwt)
        expect(token.nested?).to be(true)
      end

      it 'returns false for simple JWTs' do
        token = JWT::EncodedToken.new(inner_jwt)
        expect(token.nested?).to be(false)
      end
    end

    describe '#inner_token' do
      it 'returns the inner token for nested JWTs' do
        outer = JWT::EncodedToken.new(nested_jwt)
        inner = outer.inner_token

        expect(inner).to be_a(JWT::EncodedToken)
        expect(inner.header['alg']).to eq('HS256')
        expect(inner.unverified_payload).to eq(inner_payload)
      end

      it 'returns nil for non-nested JWTs' do
        token = JWT::EncodedToken.new(inner_jwt)
        expect(token.inner_token).to be_nil
      end
    end

    describe '#unwrap_all' do
      it 'returns all tokens for a two-level nested JWT' do
        outer = JWT::EncodedToken.new(nested_jwt)
        tokens = outer.unwrap_all(max_depth: 10)

        expect(tokens.length).to eq(2)
        expect(tokens.first).to eq(outer)
        expect(tokens.last.unverified_payload).to eq(inner_payload)
      end

      it 'returns all tokens for a deeply nested JWT' do
        level1 = JWT.encode(inner_payload, 's1', 'HS256')
        level2 = create_nested_jwt(level1, algorithm: 'HS256', key: 's2')
        level3 = create_nested_jwt(level2, algorithm: 'HS256', key: 's3')

        outer = JWT::EncodedToken.new(level3)
        tokens = outer.unwrap_all(max_depth: 10)

        expect(tokens.length).to eq(3)
        expect(tokens.last.unverified_payload).to eq(inner_payload)
      end

      it 'raises DecodeError when nesting exceeds max depth' do
        level1 = JWT.encode(inner_payload, 's1', 'HS256')
        level2 = create_nested_jwt(level1, algorithm: 'HS256', key: 's2')
        level3 = create_nested_jwt(level2, algorithm: 'HS256', key: 's3')

        outer = JWT::EncodedToken.new(level3)
        expect { outer.unwrap_all(max_depth: 2) }.to raise_error(JWT::DecodeError, 'Nested JWT exceeds maximum depth of 2')
      end

      it 'returns single-element array for non-nested JWT' do
        token = JWT::EncodedToken.new(inner_jwt)
        tokens = token.unwrap_all(max_depth: 10)

        expect(tokens.length).to eq(1)
        expect(tokens.first).to eq(token)
      end
    end
  end

  describe 'error handling' do
    it 'raises DecodeError for malformed nested JWT' do
      expect do
        JWT::EncodedToken.new('not.a.valid.jwt.at.all')
      end.not_to raise_error

      malformed = JWT::EncodedToken.new('invalid')
      expect { malformed.header }.to raise_error(JWT::DecodeError)
    end

    it 'raises VerificationError for invalid inner signature during verify!' do
      inner_jwt = JWT.encode({ sub: 'user' }, 'secret', 'HS256')
      nested_jwt = create_nested_jwt(inner_jwt, algorithm: 'HS256', key: 'outer')

      expect do
        JWT::NestedToken.new(nested_jwt).verify!(
          keys: [
            { algorithm: 'HS256', key: 'outer' },
            { algorithm: 'HS256', key: 'wrong_secret' }
          ]
        )
      end.to raise_error(JWT::VerificationError)
    end

    it 'raises VerificationError for invalid outer signature during verify!' do
      inner_jwt = JWT.encode({ sub: 'user' }, 'secret', 'HS256')
      nested_jwt = create_nested_jwt(inner_jwt, algorithm: 'HS256', key: 'outer')

      expect do
        JWT::NestedToken.new(nested_jwt).verify!(
          keys: [
            { algorithm: 'HS256', key: 'wrong_outer' },
            { algorithm: 'HS256', key: 'secret' }
          ]
        )
      end.to raise_error(JWT::VerificationError)
    end
  end

  describe 'end-to-end usage example' do
    it 'demonstrates complete nested JWT workflow' do
      inner_payload = { 'user_id' => 123, 'role' => 'admin' }
      inner_key = 'inner_secret'
      inner_jwt = JWT.encode(inner_payload, inner_key, 'HS256')

      outer_key = test_pkey('rsa-2048-private.pem')
      nested = JWT::NestedToken.new(inner_jwt)
      nested.sign!(
        algorithm: 'RS256',
        key: outer_key
      )

      tokens = JWT::NestedToken.new(nested.jwt).verify!(
        keys: [
          { algorithm: 'RS256', key: outer_key.public_key },
          { algorithm: 'HS256', key: inner_key }
        ]
      )

      expect(tokens.last.payload).to eq({ 'user_id' => 123, 'role' => 'admin' })
    end
  end
end
