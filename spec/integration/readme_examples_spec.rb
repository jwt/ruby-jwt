require_relative '../spec_helper'
require 'jwt'

describe 'README.md code test' do
  context 'algorithm usage' do
    let(:payload) { {:data => 'test'} }

    it 'NONE' do
      token = JWT.encode payload, nil, 'none'
      decoded_token = JWT.decode token, nil, false

      expect(token).to eq 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJkYXRhIjoidGVzdCJ9.'
      expect(decoded_token).to eq [
                                      {'data' => 'test'},
                                      {'typ' => 'JWT', 'alg' => 'none'}
                                  ]
    end

    it 'HMAC' do
      token = JWT.encode payload, 'my$ecretK3y', 'HS256'
      decoded_token = JWT.decode token, 'my$ecretK3y', false

      expect(token).to eq 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoidGVzdCJ9.ZxW8go9hz3ETCSfxFxpwSkYg_602gOPKearsf6DsxgY'
      expect(decoded_token).to eq [
                                      {'data' => 'test'},
                                      {'typ' => 'JWT', 'alg' => 'HS256'}
                                  ]
    end

    it 'RSA' do
      rsa_private = OpenSSL::PKey::RSA.generate 2048
      rsa_public = rsa_private.public_key

      token = JWT.encode payload, rsa_private, 'RS256'
      decoded_token = JWT.decode token, rsa_public, true, {:algorithm => 'RS256'}

      expect(decoded_token).to eq [
                                      {'data' => 'test'},
                                      {'typ' => 'JWT', 'alg' => 'RS256'}
                                  ]
    end

    it 'ECDSA' do
      ecdsa_key = OpenSSL::PKey::EC.new 'prime256v1'
      ecdsa_key.generate_key
      ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
      ecdsa_public.private_key = nil

      token = JWT.encode payload, ecdsa_key, 'ES256'
      decoded_token = JWT.decode token, ecdsa_public, true, {:algorithm => 'ES256'}

      expect(decoded_token).to eq [
                                      {'data' => 'test'},
                                      {'typ' => 'JWT', 'alg' => 'ES256'}
                                  ]
    end
  end

  context 'claims' do
    let(:hmac_secret) { 'MyP4ssW0rD' }

    context 'exp' do
      it 'without leeway' do
        exp = Time.now.to_i + 4 * 3600
        exp_payload = {:data => 'data', :exp => exp}

        token = JWT.encode exp_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, {:algorithm => 'HS256'}
        end.not_to raise_error
      end

      it 'with leeway' do
        exp = Time.now.to_i - 10
        leeway = 30 # seconds

        exp_payload = {:data => 'data', :exp => exp}

        token = JWT.encode exp_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, {:leeway => leeway, :algorithm => 'HS256'}
        end.not_to raise_error
      end
    end

    context 'nbf' do
      it 'without leeway' do
        nbf = Time.now.to_i - 3600
        nbf_payload = {:data => 'data', :nbf => nbf}
        token = JWT.encode nbf_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, {:algorithm => 'HS256'}
        end.not_to raise_error
      end

      it 'with leeway' do
        nbf = Time.now.to_i + 10
        leeway = 30
        nbf_payload = {:data => 'data', :nbf => nbf}
        token = JWT.encode nbf_payload, hmac_secret, 'HS256'

        expect do
          JWT.decode token, hmac_secret, true, {:leeway => leeway, :algorithm => 'HS256'}
        end.not_to raise_error
      end
    end

    it 'iss' do
      iss = 'My Awesome Company Inc. or https://my.awesome.website/'
      iss_payload = {:data => 'data', :iss => iss}

      token = JWT.encode iss_payload, hmac_secret, 'HS256'

      expect do

      end.not_to raise_error
    end

    context 'aud' do
      it 'array' do
        expect do

        end.not_to raise_error
      end

      it 'string' do
        expect do

        end.not_to raise_error
      end
    end

    it 'jti' do
      iat = Time.now.to_i
      hmac_secret = 'test'
      jti_raw = [hmac_secret, iat].join(':').to_s
      jti = Digest::MD5.hexdigest(jti_raw)
      jti_payload = {:data => 'data', :iat => iat, :jti => jti}

      token = JWT.encode jti_payload, hmac_secret, 'HS256'

      expect do
        JWT.decode token, hmac_secret, true, {:verify_jti => true, :algorithm => 'HS256'}
      end.not_to raise_error
    end

    context 'iat' do
      it 'without leeway' do
        expect do

        end.not_to raise_error
      end

      it 'with leeway' do
        expect do

        end.not_to raise_error
      end
    end

    it 'sub' do
      expect do

      end.not_to raise_error
    end
  end
end