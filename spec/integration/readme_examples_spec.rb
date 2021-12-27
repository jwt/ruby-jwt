# frozen_string_literal: true

RSpec.describe 'README.md code test' do
  context 'algorithm usage' do
    let(:payload) { { data: 'test' } }

    it 'NONE' do
      token = JWT.encode payload, nil, 'none'
      decoded_token = JWT.decode token, nil, false

      expect(token).to eq 'eyJhbGciOiJub25lIn0.eyJkYXRhIjoidGVzdCJ9.'
      expect(decoded_token).to eq [
        { 'data' => 'test' },
        { 'alg' => 'none' }
      ]
    end

    it 'decodes with HMAC algorithm with secret key' do
      token = JWT.encode payload, 'my$ecretK3y', 'HS256'
      decoded_token = JWT.decode token, 'my$ecretK3y', false

      expect(token).to eq 'eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoidGVzdCJ9.pNIWIL34Jo13LViZAJACzK6Yf0qnvT_BuwOxiMCPE-Y'
      expect(decoded_token).to eq [
        { 'data' => 'test' },
        { 'alg' => 'HS256' }
      ]
    end

    it 'decodes with HMAC algorithm without secret key' do
      token = JWT.encode payload, nil, 'HS256'
      decoded_token = JWT.decode token, nil, false

      expect(token).to eq 'eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoidGVzdCJ9.pVzcY2dX8JNM3LzIYeP2B1e1Wcpt1K3TWVvIYSF4x-o'
      expect(decoded_token).to eq [
        { 'data' => 'test' },
        { 'alg' => 'HS256' }
      ]
    end

    it 'RSA' do
      rsa_private = OpenSSL::PKey::RSA.generate 2048
      rsa_public = rsa_private.public_key

      token = JWT.encode payload, rsa_private, 'RS256'
      decoded_token = JWT.decode token, rsa_public, true, algorithm: 'RS256'

      expect(decoded_token).to eq [
        { 'data' => 'test' },
        { 'alg' => 'RS256' }
      ]
    end

    it 'ECDSA' do
      ecdsa_key = OpenSSL::PKey::EC.new 'prime256v1'
      ecdsa_key.generate_key
      ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
      ecdsa_public.private_key = nil

      token = JWT.encode payload, ecdsa_key, 'ES256'
      decoded_token = JWT.decode token, ecdsa_public, true, algorithm: 'ES256'

      expect(decoded_token).to eq [
        { 'data' => 'test' },
        { 'alg' => 'ES256' }
      ]
    end

    if ::Gem::Version.new(OpenSSL::VERSION) >= ::Gem::Version.new('2.1')
      it 'RSASSA-PSS' do
        rsa_private = OpenSSL::PKey::RSA.generate 2048
        rsa_public = rsa_private.public_key

        token = JWT.encode payload, rsa_private, 'PS256'
        decoded_token = JWT.decode token, rsa_public, true, algorithm: 'PS256'

        expect(decoded_token).to eq [
          { 'data' => 'test' },
          { 'alg' => 'PS256' }
        ]
      end
    end
  end

  context 'claims' do
    let(:hmac_secret) { 'MyP4ssW0rD' }

    context 'exp' do
      it 'without leeway' do
        exp = Time.now.to_i + (4 * 3600)
        exp_payload = { data: 'data', exp: exp }

        token = JWT.encode exp_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, algorithm: 'HS256'
        end.not_to raise_error
      end

      it 'with leeway' do
        exp = Time.now.to_i - 10
        leeway = 30 # seconds

        exp_payload = { data: 'data', exp: exp }

        token = JWT.encode exp_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, leeway: leeway, algorithm: 'HS256'
        end.not_to raise_error
      end
    end

    context 'nbf' do
      it 'without leeway' do
        nbf = Time.now.to_i - 3600
        nbf_payload = { data: 'data', nbf: nbf }
        token = JWT.encode nbf_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, algorithm: 'HS256'
        end.not_to raise_error
      end

      it 'with leeway' do
        nbf = Time.now.to_i + 10
        leeway = 30
        nbf_payload = { data: 'data', nbf: nbf }
        token = JWT.encode nbf_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, leeway: leeway, algorithm: 'HS256'
        end.not_to raise_error
      end
    end

    it 'iss' do
      iss = 'My Awesome Company Inc. or https://my.awesome.website/'
      iss_payload = { data: 'data', iss: iss }

      token = JWT.encode iss_payload, hmac_secret, 'HS256'

      expect do
        JWT.decode token, hmac_secret, true, iss: iss, algorithm: 'HS256'
      end.not_to raise_error
    end

    context 'aud' do
      it 'array' do
        aud = %w[Young Old]
        aud_payload = { data: 'data', aud: aud }

        token = JWT.encode aud_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, aud: %w[Old Young], verify_aud: true, algorithm: 'HS256'
        end.not_to raise_error
      end

      it 'string' do
        aud = 'Kids'
        aud_payload = { data: 'data', aud: aud }

        token = JWT.encode aud_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, aud: 'Kids', verify_aud: true, algorithm: 'HS256'
        end.not_to raise_error
      end
    end

    it 'jti' do
      iat = Time.now.to_i
      hmac_secret = 'test'
      jti_raw = [hmac_secret, iat].join(':').to_s
      jti = Digest::MD5.hexdigest(jti_raw)
      jti_payload = { data: 'data', iat: iat, jti: jti }

      token = JWT.encode jti_payload, hmac_secret, 'HS256'

      expect do
        JWT.decode token, hmac_secret, true, verify_jti: true, algorithm: 'HS256'
      end.not_to raise_error
    end

    context 'iat' do
      it 'without leeway' do
        iat = Time.now.to_i
        iat_payload = { data: 'data', iat: iat }

        token = JWT.encode iat_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, verify_iat: true, algorithm: 'HS256'
        end.not_to raise_error
      end

      it 'with leeway' do
        iat = Time.now.to_i - 7
        iat_payload = { data: 'data', iat: iat, leeway: 10 }

        token = JWT.encode iat_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, verify_iat: true, algorithm: 'HS256'
        end.not_to raise_error
      end
    end

    context 'custom header fields' do
      it 'with custom field' do
        payload = { data: 'test' }

        token = JWT.encode payload, nil, 'none', typ: 'JWT'
        _, header = JWT.decode token, nil, false

        expect(header['typ']).to eq 'JWT'
      end
    end

    it 'sub' do
      sub = 'Subject'
      sub_payload = { data: 'data', sub: sub }

      token = JWT.encode sub_payload, hmac_secret, 'HS256'

      expect do
        JWT.decode token, hmac_secret, true, 'sub' => sub, :verify_sub => true, :algorithm => 'HS256'
      end.not_to raise_error
    end

    it 'required_claims' do
      payload = { data: 'test' }

      token = JWT.encode payload, hmac_secret, 'HS256'

      expect do
        JWT.decode token, hmac_secret, true, required_claims: ['exp'], algorithm: 'HS256'
      end.to raise_error(JWT::MissingRequiredClaim)

      expect do
        JWT.decode token, hmac_secret, true, required_claims: ['data'], algorithm: 'HS256'
      end.not_to raise_error
    end

    it 'find_key' do
      issuers = %w[My_Awesome_Company1 My_Awesome_Company2]
      iss_payload = { data: 'data', iss: issuers.first }

      secrets = { issuers.first => hmac_secret, issuers.last => 'hmac_secret2' }

      token = JWT.encode iss_payload, hmac_secret, 'HS256'

      expect do
        # Add iss to the validation to check if the token has been manipulated
        JWT.decode(token, nil, true, { iss: issuers, verify_iss: true, algorithm: 'HS256' }) do |_headers, payload|
          secrets[payload['iss']]
        end
      end.not_to raise_error
    end

    it 'JWK' do
      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048))
      payload = { data: 'data' }
      headers = { kid: jwk.kid }

      token = JWT.encode(payload, jwk.keypair, 'RS512', headers)

      # The jwk loader would fetch the set of JWKs from a trusted source
      jwk_loader = ->(options) do
        @cached_keys = nil if options[:invalidate] # need to reload the keys
        @cached_keys ||= { keys: [jwk.export] }
      end
      expect do
        JWT.decode(token, nil, true, { algorithms: ['RS512'], jwks: jwk_loader})
      end.not_to raise_error
    end
  end
end
