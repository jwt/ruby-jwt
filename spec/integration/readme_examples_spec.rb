# frozen_string_literal: true

require 'logger'

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
      pending 'Different behaviour on OpenSSL 3.0 (https://github.com/openssl/openssl/issues/13089)' if JWT.openssl_3_hmac_empty_key_regression?
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
      ecdsa_key = OpenSSL::PKey::EC.generate('prime256v1')

      token = JWT.encode payload, ecdsa_key, 'ES256'
      decoded_token = JWT.decode token, ecdsa_key, true, algorithm: 'ES256'

      expect(decoded_token).to eq [
        { 'data' => 'test' },
        { 'alg' => 'ES256' }
      ]
    end

    if defined?(RbNaCl)
      it 'EDDSA' do
        eddsa_key = RbNaCl::Signatures::Ed25519::SigningKey.generate
        eddsa_public = eddsa_key.verify_key

        token = JWT.encode payload, eddsa_key, 'ED25519'
        decoded_token = JWT.decode token, eddsa_public, true, algorithm: 'ED25519'

        expect(decoded_token).to eq [
          { 'data' => 'test' },
          { 'alg' => 'ED25519' }
        ]
      end
    end

    if Gem::Version.new(OpenSSL::VERSION) >= Gem::Version.new('2.1')
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

    context 'The JWK based encode/decode routine' do
      it 'works as expected' do
        # ---------- ENCODE ----------
        optional_parameters = { kid: 'my-kid', use: 'sig', alg: 'RS512' }
        jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048), optional_parameters)

        # Encoding
        payload = { data: 'data' }
        token = JWT.encode(payload, jwk.signing_key, jwk[:alg], kid: jwk[:kid])

        # JSON Web Key Set for advertising your signing keys
        jwks_hash = JWT::JWK::Set.new(jwk).export

        # ---------- DECODE ----------
        jwks = JWT::JWK::Set.new(jwks_hash)
        jwks.filter! { |key| key[:use] == 'sig' } # Signing keys only!
        algorithms = jwks.map { |key| key[:alg] }.compact.uniq
        JWT.decode(token, nil, true, algorithms: algorithms, jwks: jwks)
      end
    end

    context 'The JWKS loader example' do
      let(:logger_output) { StringIO.new }
      let(:logger) { Logger.new(logger_output) }

      it 'works as expected (legacy)' do
        jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048), 'optional-kid')
        payload = { data: 'data' }
        headers = { kid: jwk.kid }

        token = JWT.encode(payload, jwk.signing_key, 'RS512', headers)

        # The jwk loader would fetch the set of JWKs from a trusted source,
        # to avoid malicious invalidations some kind of protection needs to be implemented.
        # This example only allows cache invalidations every 5 minutes.
        jwk_loader = ->(options) do
          if options[:kid_not_found] && @cache_last_update < Time.now.to_i - 300
            logger.info("Invalidating JWK cache. #{options[:kid]} not found from previous cache")
            @cached_keys = nil
          end
          @cached_keys ||= begin
            @cache_last_update = Time.now.to_i
            { keys: [jwk.export] }
          end
        end

        begin
          JWT.decode(token, nil, true, { algorithms: ['RS512'], jwks: jwk_loader })
        rescue JWT::JWKError
          # Handle problems with the provided JWKs
        rescue JWT::DecodeError
          # Handle other decode related issues e.g. no kid in header, no matching public key found etc.
        end

        ## This is not in the example but verifies that the cache is invalidated after 5 minutes
        jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048), 'new-kid')

        headers = { kid: jwk.kid }

        token = JWT.encode(payload, jwk.signing_key, 'RS512', headers)
        @cache_last_update = Time.now.to_i - 301

        JWT.decode(token, nil, true, { algorithms: ['RS512'], jwks: jwk_loader })
        expect(logger_output.string.chomp).to match(/^I, .* : Invalidating JWK cache. new-kid not found from previous cache/)

        jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048), 'yet-another-new-kid')
        headers = { kid: jwk.kid }
        token = JWT.encode(payload, jwk.signing_key, 'RS512', headers)
        expect { JWT.decode(token, nil, true, { algorithms: ['RS512'], jwks: jwk_loader }) }.to raise_error(JWT::DecodeError, 'Could not find public key for kid yet-another-new-kid')
      end

      it 'works as expected' do
        jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048), use: 'sig')
        jwks_hash = JWT::JWK::Set.new(jwk)
        payload = { data: 'data' }
        headers = { kid: jwk.kid }

        token = JWT.encode(payload, jwk.signing_key, 'RS512', headers)

        jwks_loader = ->(options) do
          # The jwk loader would fetch the set of JWKs from a trusted source.
          # To avoid malicious requests triggering cache invalidations there needs to be
          # some kind of grace time or other logic for determining the validity of the invalidation.
          # This example only allows cache invalidations every 5 minutes.
          if options[:kid_not_found] && @cache_last_update < Time.now.to_i - 300
            logger.info("Invalidating JWK cache. #{options[:kid]} not found from previous cache")
            @cached_keys = nil
          end
          @cached_keys ||= begin
            @cache_last_update = Time.now.to_i
            # Replace with your own JWKS fetching routine
            jwks = JWT::JWK::Set.new(jwks_hash)
            jwks.select! { |key| key[:use] == 'sig' } # Signing Keys only
            jwks
          end
        end

        begin
          JWT.decode(token, nil, true, { algorithms: ['RS512'], jwks: jwks_loader })
        rescue JWT::JWKError
          # Handle problems with the provided JWKs
        rescue JWT::DecodeError
          # Handle other decode related issues e.g. no kid in header, no matching public key found etc.
        end
      end
    end

    it 'JWK import and export' do
      # Import a JWK Hash (showing an HMAC example)
      _jwk = JWT::JWK.new({ kty: 'oct', k: 'my-secret', kid: 'my-kid' })

      # Import an OpenSSL key
      # You can optionally add descriptive parameters to the JWK
      desc_params = { kid: 'my-kid', use: 'sig' }
      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048), desc_params)

      # Export as JWK Hash (public key only by default)
      _jwk_hash = jwk.export
      _jwk_hash_with_private_key = jwk.export(include_private: true)

      # Export as OpenSSL key
      _public_key = jwk.verify_key
      _private_key = jwk.signing_key if jwk.private?

      # You can also import and export entire JSON Web Key Sets
      jwks_hash = { keys: [{ kty: 'oct', k: 'my-secret', kid: 'my-kid' }] }
      jwks = JWT::JWK::Set.new(jwks_hash)
      _jwks_hash = jwks.export
    end

    it 'JWK with thumbprint as kid via symbol' do
      JWT.configuration.jwk.kid_generator_type = :rfc7638_thumbprint

      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048))

      jwk_hash = jwk.export

      expect(jwk_hash[:kid].size).to eq(43)
    end

    it 'JWK with thumbprint as kid via type' do
      JWT.configuration.jwk.kid_generator = JWT::JWK::Thumbprint

      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048))

      jwk_hash = jwk.export

      expect(jwk_hash[:kid].size).to eq(43)
    end

    it 'JWK with thumbprint given in the initializer (legacy)' do
      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048), kid_generator: JWT::JWK::Thumbprint)

      jwk_hash = jwk.export

      expect(jwk_hash[:kid].size).to eq(43)
    end

    it 'JWK with thumbprint given in the initializer' do
      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048), nil, kid_generator: JWT::JWK::Thumbprint)

      jwk_hash = jwk.export

      expect(jwk_hash[:kid].size).to eq(43)
    end
  end

  context 'custom algorithm example' do
    it 'allows a module to be used as algorithm on encode and decode' do
      custom_hs512_alg = Module.new do
        def self.alg
          'HS512'
        end

        def self.valid_alg?(alg_to_validate)
          alg_to_validate == alg
        end

        def self.sign(data:, signing_key:)
          OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha512'), data, signing_key)
        end

        def self.verify(data:, signature:, verification_key:)
          sign(data: data, signing_key: verification_key) == signature
        end
      end

      token = JWT.encode({ 'pay' => 'load' }, 'secret', custom_hs512_alg)
      _payload, _header = JWT.decode(token, 'secret', true, algorithm: custom_hs512_alg)
    end
  end
end
