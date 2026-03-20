# frozen_string_literal: true

RSpec.describe JWT::EncodedNestedToken do
  let(:inner_secret) { 'inner_secret_key' }
  let(:outer_secret) { 'outer_secret_key' }
  let(:inner_payload) { { 'user_id' => 123, 'role' => 'admin' } }

  def create_signed_jwt(payload: inner_payload, algorithm: 'HS256', key: inner_secret)
    token = JWT::Token.new(payload: payload)
    token.sign!(algorithm: algorithm, key: key)
    token.jwt
  end

  def create_nested(inner, algorithm:, key:)
    JWT::NestedToken.new(inner).tap { |n| n.sign!(algorithm: algorithm, key: key) }.jwt
  end

  let(:inner_jwt) { create_signed_jwt }

  describe 'Enumerable interface' do
    let(:nested_jwt) { create_nested(inner_jwt, algorithm: 'HS256', key: outer_secret) }

    it 'has the correct number of tokens' do
      nested = described_class.new(nested_jwt)
      expect(nested.count).to eq(2)
    end

    it 'orders tokens from outermost to innermost' do
      nested = described_class.new(nested_jwt)
      headers = nested.map(&:header)

      expect(headers.first['cty']).to eq('JWT')
      expect(headers.last).not_to have_key('cty')
    end

    it 'returns a single token for a non-nested JWT' do
      nested = described_class.new(inner_jwt)
      expect(nested.count).to eq(1)
    end

    it 'supports three nesting levels' do
      level2 = create_nested(inner_jwt, algorithm: 'HS256', key: 'key2')
      level3 = create_nested(level2, algorithm: 'HS384', key: 'key3')

      nested = described_class.new(level3)
      expect(nested.count).to eq(3)

      algorithms = nested.map { |t| t.header['alg'] }
      expect(algorithms).to eq(%w[HS384 HS256 HS256])
    end
  end

  describe '#last' do
    it 'raises DecodeError before verification' do
      nested_jwt = create_nested(inner_jwt, algorithm: 'HS256', key: outer_secret)
      nested = described_class.new(nested_jwt)

      expect { nested.last }.to raise_error(JWT::DecodeError, /Verify the token before/)
    end

    it 'returns the innermost token after verification' do
      nested_jwt = create_nested(inner_jwt, algorithm: 'HS256', key: outer_secret)
      nested = described_class.new(nested_jwt)
      nested.verify!(algorithm: 'HS256', key: [outer_secret, inner_secret])

      expect(nested.last.payload).to eq(inner_payload)
    end
  end

  describe '#verify!' do
    let(:nested_jwt) { create_nested(inner_jwt, algorithm: 'HS256', key: outer_secret) }

    it 'verifies signatures and returns self' do
      nested = described_class.new(nested_jwt)
      result = nested.verify!(algorithm: 'HS256', key: [outer_secret, inner_secret])

      expect(result).to eq(nested)
    end

    it 'allows accessing innermost payload after verification' do
      nested = described_class.new(nested_jwt)
      nested.verify!(algorithm: 'HS256', key: [outer_secret, inner_secret])

      expect(nested.last.payload).to eq(inner_payload)
    end

    it 'verifies claims on the innermost token' do
      nested = described_class.new(nested_jwt)
      nested.verify!(algorithm: 'HS256', key: [outer_secret, inner_secret])

      expect { nested.last.payload }.not_to raise_error
    end

    it 'raises VerificationError when no key matches' do
      nested = described_class.new(nested_jwt)

      expect do
        nested.verify!(algorithm: 'HS256', key: 'wrong_key')
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end

    it 'works with a single shared key for all levels' do
      shared_key = 'shared_secret'
      inner = create_signed_jwt(key: shared_key)
      nested_jwt = create_nested(inner, algorithm: 'HS256', key: shared_key)

      nested = described_class.new(nested_jwt)
      nested.verify!(algorithm: 'HS256', key: shared_key)

      expect(nested.last.payload).to eq(inner_payload)
    end

    it 'handles case-insensitive cty header' do
      signer = JWT::JWA.create_signer(algorithm: 'HS256', key: outer_secret)
      header = { 'cty' => 'jwt' }.merge(signer.jwa.header) { |_k, old, _new| old }
      encoded_header = JWT::Base64.url_encode(JWT::JSON.generate(header))
      encoded_payload = JWT::Base64.url_encode(inner_jwt)
      signature = signer.sign(data: "#{encoded_header}.#{encoded_payload}")
      lowercase_nested = "#{encoded_header}.#{encoded_payload}.#{JWT::Base64.url_encode(signature)}"

      nested = described_class.new(lowercase_nested)
      nested.verify!(algorithm: 'HS256', key: [outer_secret, inner_secret])

      expect(nested.last.payload).to eq(inner_payload)
    end

    context 'with different algorithms at each level' do
      let(:rsa_private) { test_pkey('rsa-2048-private.pem') }
      let(:rsa_public) { rsa_private.public_key }

      it 'supports mixed algorithms via key_finder' do
        nested_jwt = create_nested(inner_jwt, algorithm: 'RS256', key: rsa_private)

        key_map = {
          'RS256' => rsa_public,
          'HS256' => inner_secret
        }

        nested = described_class.new(nested_jwt)
        nested.verify!(
          algorithm: %w[RS256 HS256],
          key_finder: ->(token) { key_map[token.header['alg']] }
        )

        expect(nested.last.payload).to eq(inner_payload)
      end
    end

    context 'with multiple nesting levels' do
      it 'verifies all levels with same algorithm family' do
        level2 = create_nested(inner_jwt, algorithm: 'HS384', key: 'key2')
        level3 = create_nested(level2, algorithm: 'HS512', key: 'key3')

        nested = described_class.new(level3)
        nested.verify!(
          algorithm: %w[HS512 HS384 HS256],
          key: ['key3', 'key2', inner_secret]
        )

        expect(nested.last.payload).to eq(inner_payload)
      end
    end
  end

  describe 'max_depth' do
    it 'raises DecodeError when nesting exceeds MAX_DEPTH' do
      current = inner_jwt
      (described_class::MAX_DEPTH + 1).times do |i|
        current = create_nested(current, algorithm: 'HS256', key: "key_#{i}")
      end

      nested = described_class.new(current)
      expect do
        nested.count
      end.to raise_error(JWT::DecodeError, /exceeds maximum depth/)
    end

    it 'allows overriding max_depth via constructor' do
      level2 = create_nested(inner_jwt, algorithm: 'HS256', key: 'key2')
      level3 = create_nested(level2, algorithm: 'HS256', key: 'key3')

      expect do
        described_class.new(level3, max_depth: 2).count
      end.to raise_error(JWT::DecodeError, 'Nested JWT exceeds maximum depth of 2')

      expect do
        described_class.new(level3, max_depth: 5).count
      end.not_to raise_error
    end
  end
end
