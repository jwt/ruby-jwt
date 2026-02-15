# frozen_string_literal: true

RSpec.describe 'Duplicate Claim Name Detection' do
  let(:secret) { 'test_secret' }
  let(:algorithm) { 'HS256' }

  def sign_jwt(signing_input, secret)
    signature = OpenSSL::HMAC.digest('SHA256', secret, signing_input)
    JWT::Base64.url_encode(signature)
  end

  def build_jwt_with_duplicate_payload(duplicate_payload_json)
    header = JWT::Base64.url_encode('{"alg":"HS256"}')
    payload = JWT::Base64.url_encode(duplicate_payload_json)
    signing_input = "#{header}.#{payload}"
    signature = sign_jwt(signing_input, secret)
    "#{signing_input}.#{signature}"
  end

  def build_jwt_with_duplicate_header(duplicate_header_json, payload_json = '{"sub":"user"}')
    header = JWT::Base64.url_encode(duplicate_header_json)
    payload = JWT::Base64.url_encode(payload_json)
    signing_input = "#{header}.#{payload}"
    signature = sign_jwt(signing_input, secret)
    "#{signing_input}.#{signature}"
  end

  describe 'using EncodedToken API' do
    describe 'payload with duplicate keys' do
      let(:duplicate_payload_jwt) { build_jwt_with_duplicate_payload('{"sub":"user","sub":"admin"}') }

      context 'with default behavior' do
        it 'uses the last value (allows duplicates)' do
          token = JWT::EncodedToken.new(duplicate_payload_jwt)
          expect(token.unverified_payload['sub']).to eq('admin')
        end
      end

      context 'with raise_on_duplicate_keys!' do
        it 'raises DuplicateKeyError', if: JWT::JSON.supports_duplicate_key_detection? do
          token = JWT::EncodedToken.new(duplicate_payload_jwt)
          token.raise_on_duplicate_keys!
          expect do
            token.unverified_payload
          end.to raise_error(JWT::DuplicateKeyError, /duplicate key/)
        end

        it 'raises UnsupportedError', unless: JWT::JSON.supports_duplicate_key_detection? do
          token = JWT::EncodedToken.new(duplicate_payload_jwt)
          expect do
            token.raise_on_duplicate_keys!
          end.to raise_error(JWT::UnsupportedError, /JSON gem >= 2\.13\.0/)
        end
      end
    end

    describe 'header with duplicate keys' do
      let(:duplicate_header_jwt) { build_jwt_with_duplicate_header('{"alg":"HS256","alg":"none"}') }

      context 'with default behavior' do
        it 'uses the last value (allows duplicates)' do
          token = JWT::EncodedToken.new(duplicate_header_jwt)
          expect(token.header['alg']).to eq('none')
        end
      end

      context 'with raise_on_duplicate_keys!' do
        it 'raises DuplicateKeyError for header', if: JWT::JSON.supports_duplicate_key_detection? do
          token = JWT::EncodedToken.new(duplicate_header_jwt)
          token.raise_on_duplicate_keys!
          expect do
            token.header
          end.to raise_error(JWT::DuplicateKeyError, /duplicate key/)
        end

        it 'raises UnsupportedError', unless: JWT::JSON.supports_duplicate_key_detection? do
          token = JWT::EncodedToken.new(duplicate_header_jwt)
          expect do
            token.raise_on_duplicate_keys!
          end.to raise_error(JWT::UnsupportedError, /JSON gem >= 2\.13\.0/)
        end
      end
    end

    describe 'chaining', if: JWT::JSON.supports_duplicate_key_detection? do
      let(:valid_jwt) { build_jwt_with_duplicate_payload('{"sub":"user"}') }

      it 'returns self for method chaining' do
        token = JWT::EncodedToken.new(valid_jwt)
        expect(token.raise_on_duplicate_keys!).to eq(token)
      end
    end

    describe 'valid tokens', if: JWT::JSON.supports_duplicate_key_detection? do
      let(:valid_jwt) { build_jwt_with_duplicate_payload('{"sub":"user","name":"John"}') }

      it 'parses valid JSON without duplicates' do
        token = JWT::EncodedToken.new(valid_jwt)
        token.raise_on_duplicate_keys!
        expect(token.unverified_payload).to eq({ 'sub' => 'user', 'name' => 'John' })
      end
    end
  end

  describe 'multiple duplicate keys' do
    let(:multiple_duplicates_jwt) { build_jwt_with_duplicate_payload('{"a":1,"b":2,"a":3,"b":4}') }

    context 'with raise_on_duplicate_keys!' do
      it 'raises DuplicateKeyError for the first duplicate found', if: JWT::JSON.supports_duplicate_key_detection? do
        token = JWT::EncodedToken.new(multiple_duplicates_jwt)
        token.raise_on_duplicate_keys!
        expect do
          token.unverified_payload
        end.to raise_error(JWT::DuplicateKeyError, /duplicate key/)
      end

      it 'raises UnsupportedError', unless: JWT::JSON.supports_duplicate_key_detection? do
        token = JWT::EncodedToken.new(multiple_duplicates_jwt)
        expect do
          token.raise_on_duplicate_keys!
        end.to raise_error(JWT::UnsupportedError, /JSON gem >= 2\.13\.0/)
      end
    end
  end
end
