# frozen_string_literal: true

RSpec.describe JWT::NestedToken do
  let(:inner_secret) { 'inner_secret_key' }
  let(:inner_payload) { { 'user_id' => 123, 'role' => 'admin' } }

  def create_inner_jwt(payload: inner_payload, algorithm: 'HS256', key: inner_secret)
    token = JWT::Token.new(payload: payload)
    token.sign!(algorithm: algorithm, key: key)
    token.jwt
  end

  describe '#sign!' do
    it 'creates a nested JWT with cty header set to JWT' do
      nested = described_class.new(create_inner_jwt)
      nested.sign!(algorithm: 'HS256', key: 'outer_secret')

      outer = JWT::EncodedToken.new(nested.jwt)
      expect(outer.header['cty']).to eq('JWT')
      expect(outer.header['alg']).to eq('HS256')
    end

    it 'base64url-encodes the inner JWT directly without JSON wrapping' do
      inner_jwt = create_inner_jwt
      nested = described_class.new(inner_jwt)
      nested.sign!(algorithm: 'HS256', key: 'outer_secret')

      encoded_payload = nested.jwt.split('.')[1]
      expect(JWT::Base64.url_decode(encoded_payload)).to eq(inner_jwt)
    end

    it 'produces a verifiable signature' do
      nested = described_class.new(create_inner_jwt)
      nested.sign!(algorithm: 'HS256', key: 'outer_secret')

      outer = JWT::EncodedToken.new(nested.jwt)
      expect { outer.verify_signature!(algorithm: 'HS256', key: 'outer_secret') }.not_to raise_error
    end

    it 'allows additional header fields' do
      nested = described_class.new(create_inner_jwt)
      nested.header['kid'] = 'my-key-id'
      nested.sign!(algorithm: 'HS256', key: 'outer_secret')

      outer = JWT::EncodedToken.new(nested.jwt)
      expect(outer.header['kid']).to eq('my-key-id')
      expect(outer.header['cty']).to eq('JWT')
    end

    context 'with RSA algorithm' do
      let(:rsa_private) { test_pkey('rsa-2048-private.pem') }
      let(:rsa_public) { rsa_private.public_key }

      it 'creates a nested JWT signed with RSA' do
        nested = described_class.new(create_inner_jwt)
        nested.sign!(algorithm: 'RS256', key: rsa_private)

        outer = JWT::EncodedToken.new(nested.jwt)
        expect(outer.header['alg']).to eq('RS256')
        expect(outer.header['cty']).to eq('JWT')

        expect { outer.verify_signature!(algorithm: 'RS256', key: rsa_public) }.not_to raise_error
      end
    end
  end

  describe 'multi-level nesting' do
    it 'supports wrapping a nested JWT again' do
      level1 = described_class.new(create_inner_jwt)
      level1.sign!(algorithm: 'HS256', key: 'key1')

      level2 = described_class.new(level1.jwt)
      level2.sign!(algorithm: 'HS384', key: 'key2')

      outer = JWT::EncodedToken.new(level2.jwt)
      expect(outer.header['alg']).to eq('HS384')
      expect(outer.header['cty']).to eq('JWT')
    end
  end
end
