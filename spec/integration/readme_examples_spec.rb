# frozen_string_literal: true

require 'logger'
require 'securerandom'

RSpec.describe 'README.md code test' do
  let(:hmac_secret) { 'my$ecretK3y' }

  context 'algorithm usage' do
    let(:payload) { { data: 'test' } }

    it 'NONE' do
      token = JWT.encode(payload, nil, 'none')
      decoded_token = JWT.decode(token, nil, true, { algorithm: 'none' })

      expect(token).to eq('eyJhbGciOiJub25lIn0.eyJkYXRhIjoidGVzdCJ9.')
      expect(decoded_token).to eq([{ 'data' => 'test' }, { 'alg' => 'none' }])
    end

    it 'decodes with HMAC algorithm with secret key' do
      token = JWT.encode(payload, hmac_secret, 'HS256')
      decoded_token = JWT.decode(token, hmac_secret, true, { algorithm: 'HS256' })

      expect(token).to eq('eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoidGVzdCJ9.pNIWIL34Jo13LViZAJACzK6Yf0qnvT_BuwOxiMCPE-Y')
      expect(decoded_token).to eq([{ 'data' => 'test' }, { 'alg' => 'HS256' }])
    end

    it 'RSA' do
      rsa_private = OpenSSL::PKey::RSA.generate(2048)
      rsa_public  = rsa_private.public_key

      token = JWT.encode(payload, rsa_private, 'RS256')
      decoded_token = JWT.decode(token, rsa_public, true, { algorithm: 'RS256' })

      expect(decoded_token).to eq([{ 'data' => 'test' }, { 'alg' => 'RS256' }])
    end

    it 'ECDSA' do
      ecdsa_private = OpenSSL::PKey::EC.generate('prime256v1')
      skip 'OpenSSL::PKey::EC#public_to_der requires openssl 3.0 or later' unless ecdsa_private.respond_to?(:public_to_der)

      ecdsa_public = OpenSSL::PKey::EC.new(ecdsa_private.public_to_der)

      token = JWT.encode(payload, ecdsa_private, 'ES256')
      decoded_token = JWT.decode(token, ecdsa_public, true, { algorithm: 'ES256' })

      expect(decoded_token).to eq([{ 'data' => 'test' }, { 'alg' => 'ES256' }])
    end

    if Gem::Version.new(OpenSSL::VERSION) >= Gem::Version.new('2.1')
      it 'RSASSA-PSS' do
        rsa_private = OpenSSL::PKey::RSA.generate(2048)
        rsa_public  = rsa_private.public_key

        token = JWT.encode(payload, rsa_private, 'PS256')
        decoded_token = JWT.decode(token, rsa_public, true, { algorithm: 'PS256' })

        expect(decoded_token).to eq([{ 'data' => 'test' }, { 'alg' => 'PS256' }])
      end
    end

    it 'custom algorithm' do
      custom_hs512_alg = Module.new do
        extend JWT::JWA::SigningAlgorithm

        def self.alg
          'HS512'
        end

        def self.sign(data:, signing_key:)
          OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha512'), signing_key, data)
        end

        def self.verify(data:, signature:, verification_key:)
          sign(data: data, signing_key: verification_key) == signature
        end
      end

      token = JWT.encode(payload, hmac_secret, custom_hs512_alg)
      decoded_token = JWT.decode(token, hmac_secret, true, { algorithm: custom_hs512_alg })

      expect(token).to eq('eyJhbGciOiJIUzUxMiJ9.eyJkYXRhIjoidGVzdCJ9.A1E4QkK-YRAJCS8jhhClibuZNdKxUopEOVrQNTZAN9y4PhGMNVyfKrIMycTNtOEwdei70ZTDOXobeiLa4mwDkw')
      expect(decoded_token).to eq([{ 'data' => 'test' }, { 'alg' => 'HS512' }])
    end

    it 'custom header fields' do
      token = JWT.encode(payload, nil, 'none', { typ: 'JWT' })
      decoded_token = JWT.decode(token, nil, true, { algorithm: 'none' })

      expect(token).to eq('eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJkYXRhIjoidGVzdCJ9.')
      expect(decoded_token).to eq([{ 'data' => 'test' }, { 'typ' => 'JWT', 'alg' => 'none' }])
    end
  end

  context 'JWT::Token and JWT::EncodedToken' do
    let(:payload) { { exp: Time.now.to_i + 60, jti: '1234', sub: 'my-subject' } }
    let(:header) { { kid: 'hmac' } }
    let(:token) do
      JWT::Token.new(payload: payload, header: header).tap do |token|
        token.sign!(algorithm: 'HS256', key: hmac_secret)
      end
    end

    it 'verifies the signature and claims before giving the payload' do
      encoded_token = JWT::EncodedToken.new(token.jwt)

      expect { encoded_token.verify_signature!(algorithm: 'HS256', key: 'wrong_secret') }.to raise_error(JWT::VerificationError)
      expect { encoded_token.verify_claims!(sub: ['not-my-subject']) }.to raise_error(JWT::InvalidSubError)
      expect(encoded_token.claim_errors(sub: ['not-my-subject']).map(&:message)).to eq(['Invalid subject. Expected ["not-my-subject"], received my-subject'])

      encoded_token.verify_signature!(algorithm: 'HS256', key: hmac_secret)
      encoded_token.verify_claims!(:exp, :jti)

      expect(encoded_token.payload).to eq('exp' => payload[:exp], 'jti' => '1234', 'sub' => 'my-subject')
      expect(encoded_token.header).to eq('kid' => 'hmac', 'alg' => 'HS256')
    end

    it 'verifies the signature and claims in one go' do
      encoded_token = JWT::EncodedToken.new(token.jwt)
      encoded_token.verify!(signature: { algorithm: 'HS256', key: hmac_secret })

      expect(encoded_token.payload).to eq('exp' => payload[:exp], 'jti' => '1234', 'sub' => 'my-subject')
    end

    it 'signs and verifies with a JWK' do
      jwk_json = '{
        "kty": "oct",
        "k": "bXkkZWNyZXRLM3k",
        "alg": "HS256",
        "kid": "hmac"
      }'

      jwk = JWT::JWK.import(JSON.parse(jwk_json))

      token = JWT::Token.new(payload: payload, header: header)
      token.sign!(algorithm: 'HS256', key: jwk)

      encoded_token = JWT::EncodedToken.new(token.jwt)
      expect { encoded_token.verify!(signature: { algorithm: %w[HS256 HS512], key: jwk }) }.not_to raise_error
      expect(token.jwt).to eq(JWT::Token.new(payload: payload, header: header).tap { |t| t.sign!(algorithm: 'HS256', key: hmac_secret) }.jwt)
    end

    it 'verifies with the JWK key finder' do
      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048))
      token = JWT::Token.new(payload: { data: 'test' }, header: { kid: jwk.kid })
      token.sign!(algorithm: 'RS256', key: jwk.signing_key)

      key_finder = JWT::JWK::KeyFinder.new(jwks: JWT::JWK::Set.new(jwk))
      encoded_token = JWT::EncodedToken.new(token.jwt)
      encoded_token.verify!(signature: { algorithm: 'RS256', key_finder: key_finder })

      expect(encoded_token.payload).to eq('data' => 'test')
    end

    it 'verifies with a custom key finder' do
      rsa_private = OpenSSL::PKey::RSA.generate(2048)
      rsa_public  = rsa_private.public_key
      token = JWT::Token.new(payload: { data: 'test' })
      token.sign!(algorithm: 'RS256', key: rsa_private)

      encoded_token = JWT::EncodedToken.new(token.jwt)
      encoded_token.verify!(signature: { algorithm: 'RS256', key_finder: ->(_token) { rsa_public } })

      expect(encoded_token.payload).to eq('data' => 'test')
    end

    it 'detaches the payload' do
      token = JWT::Token.new(payload: { data: 'test' })
      token.sign!(algorithm: 'HS256', key: hmac_secret)
      token.detach_payload!

      expect(token.jwt).to eq('eyJhbGciOiJIUzI1NiJ9..pNIWIL34Jo13LViZAJACzK6Yf0qnvT_BuwOxiMCPE-Y')
      expect(token.encoded_payload).to eq('eyJkYXRhIjoidGVzdCJ9')

      encoded_token = JWT::EncodedToken.new(token.jwt)
      encoded_token.encoded_payload = 'eyJkYXRhIjoidGVzdCJ9'
      encoded_token.verify!(signature: { algorithm: 'HS256', key: hmac_secret })

      expect(encoded_token.payload).to eq('data' => 'test')
    end
  end

  context 'claims' do
    context 'exp' do
      it 'without leeway' do
        exp = Time.now.to_i + (4 * 3600)
        exp_payload = { data: 'test', exp: exp }

        token = JWT.encode(exp_payload, hmac_secret, 'HS256')

        expect do
          JWT.decode(token, hmac_secret, true, { algorithm: 'HS256' })
        end.not_to raise_error
      end

      it 'with leeway' do
        exp = Time.now.to_i - 10
        leeway = 30 # seconds

        exp_payload = { data: 'test', exp: exp }

        token = JWT.encode(exp_payload, hmac_secret, 'HS256')

        expect do
          JWT.decode(token, hmac_secret, true, { exp_leeway: leeway, algorithm: 'HS256' })
        end.not_to raise_error
      end
    end

    context 'nbf' do
      it 'without leeway' do
        nbf = Time.now.to_i - 3600
        nbf_payload = { data: 'test', nbf: nbf }
        token = JWT.encode(nbf_payload, hmac_secret, 'HS256')

        expect do
          JWT.decode(token, hmac_secret, true, { algorithm: 'HS256' })
        end.not_to raise_error
      end

      it 'with leeway' do
        nbf = Time.now.to_i + 10
        leeway = 30 # seconds
        nbf_payload = { data: 'test', nbf: nbf }
        token = JWT.encode(nbf_payload, hmac_secret, 'HS256')

        expect do
          JWT.decode(token, hmac_secret, true, { nbf_leeway: leeway, algorithm: 'HS256' })
        end.not_to raise_error
      end
    end

    context 'iss' do
      let(:iss) { 'My Awesome Company Inc. or https://my.awesome.website/' }
      let(:token) { JWT.encode({ data: 'test', iss: iss }, hmac_secret, 'HS256') }

      it 'with a String' do
        expect do
          JWT.decode(token, hmac_secret, true, { iss: iss, verify_iss: true, algorithm: 'HS256' })
        end.not_to raise_error
      end

      it 'with a Regexp' do
        expect do
          JWT.decode(token, hmac_secret, true, { iss: %r{https://my.awesome.website/}, verify_iss: true, algorithm: 'HS256' })
        end.not_to raise_error
      end

      it 'with a Proc' do
        expect do
          JWT.decode(token, hmac_secret, true, { iss: ->(issuer) { issuer.start_with?('My Awesome Company Inc') }, verify_iss: true, algorithm: 'HS256' })
        end.not_to raise_error
      end

      it 'with a Method' do
        valid_issuer = ->(issuer) { issuer == iss }.method(:call)

        expect do
          JWT.decode(token, hmac_secret, true, { iss: valid_issuer, verify_iss: true, algorithm: 'HS256' })
        end.not_to raise_error
      end
    end

    context 'aud' do
      it 'array' do
        aud = %w[Young Old]
        aud_payload = { data: 'test', aud: aud }

        token = JWT.encode(aud_payload, hmac_secret, 'HS256')

        expect do
          JWT.decode(token, hmac_secret, true, { aud: aud, verify_aud: true, algorithm: 'HS256' })
        end.not_to raise_error

        expect do
          JWT.decode(token, hmac_secret, true, { aud: %w[Old Young], verify_aud: true, algorithm: 'HS256' })
        end.not_to raise_error
      end

      it 'string' do
        aud = 'Kids'
        aud_payload = { data: 'test', aud: aud }

        token = JWT.encode(aud_payload, hmac_secret, 'HS256')

        expect do
          JWT.decode(token, hmac_secret, true, { aud: 'Kids', verify_aud: true, algorithm: 'HS256' })
        end.not_to raise_error
      end
    end

    it 'jti' do
      jti = SecureRandom.uuid
      jti_payload = { data: 'test', jti: jti }

      token = JWT.encode(jti_payload, hmac_secret, 'HS256')

      expect do
        JWT.decode(token, hmac_secret, true, { verify_jti: true, algorithm: 'HS256' })
      end.not_to raise_error

      expect do
        JWT.decode(token, hmac_secret, true, { verify_jti: ->(given_jti) { given_jti == jti }, algorithm: 'HS256' })
      end.not_to raise_error

      expect do
        JWT.decode(token, hmac_secret, true, { verify_jti: ->(given_jti, payload) { given_jti == jti && payload['data'] == 'test' }, algorithm: 'HS256' })
      end.not_to raise_error

      expect do
        JWT.decode(token, hmac_secret, true, { verify_jti: ->(_jti) { false }, algorithm: 'HS256' })
      end.to raise_error(JWT::InvalidJtiError)
    end

    context 'iat' do
      it 'without leeway' do
        iat = Time.now.to_i
        iat_payload = { data: 'test', iat: iat }

        token = JWT.encode(iat_payload, hmac_secret, 'HS256')

        expect do
          JWT.decode(token, hmac_secret, true, { verify_iat: true, algorithm: 'HS256' })
        end.not_to raise_error
      end

      it 'with leeway' do
        iat = Time.now.to_i + 10
        iat_payload = { data: 'test', iat: iat }

        token = JWT.encode(iat_payload, hmac_secret, 'HS256')

        expect do
          JWT.decode(token, hmac_secret, true, { verify_iat: true, algorithm: 'HS256' })
        end.to raise_error(JWT::InvalidIatError)

        expect do
          JWT.decode(token, hmac_secret, true, { verify_iat: { leeway: 30 }, algorithm: 'HS256' })
        end.not_to raise_error
      end
    end

    it 'sub' do
      sub = 'Subject'
      sub_payload = { data: 'test', sub: sub }

      token = JWT.encode(sub_payload, hmac_secret, 'HS256')

      expect do
        JWT.decode(token, hmac_secret, true, { sub: sub, verify_sub: true, algorithm: 'HS256' })
      end.not_to raise_error

      expect do
        JWT.decode(token, hmac_secret, true, { sub: 'sub', verify_sub: true, algorithm: 'HS256' })
      end.to raise_error(JWT::InvalidSubError)

      expect do
        JWT.decode(token, hmac_secret, true, { 'sub' => 'sub', verify_sub: true, algorithm: 'HS256' })
      end.not_to raise_error
    end

    it 'standalone claim verification' do
      expect { JWT::Claims.verify_payload!({ 'exp' => Time.now.to_i + 10 }, :numeric, :exp) }.not_to raise_error
      expect(JWT::Claims.valid_payload?({ 'exp' => Time.now.to_i + 10 }, :exp)).to be(true)
      expect(JWT::Claims.payload_errors({ 'exp' => Time.now.to_i - 10 }, :exp).map(&:message)).to eq(['Signature has expired'])
      expect { JWT::Claims.verify_payload!({ 'exp' => Time.now.to_i - 10 }, exp: { leeway: 11 }) }.not_to raise_error
      expect { JWT::Claims.verify_payload!({ 'exp' => Time.now.to_i + 10, 'sub' => 'subject' }, :exp, sub: 'subject') }.not_to raise_error
    end

    it 'required_claims' do
      payload = { data: 'test' }

      token = JWT.encode(payload, hmac_secret, 'HS256')

      expect do
        JWT.decode(token, hmac_secret, true, { required_claims: ['exp'], algorithm: 'HS256' })
      end.to raise_error(JWT::MissingRequiredClaim)

      expect do
        JWT.decode(token, hmac_secret, true, { required_claims: ['data'], algorithm: 'HS256' })
      end.not_to raise_error
    end

    it 'find_key' do
      issuers = %w[My_Awesome_Company1 My_Awesome_Company2]
      iss_payload = { data: 'test', iss: issuers.first }

      secrets = { issuers.first => hmac_secret, issuers.last => 'hmac_secret2' }

      token = JWT.encode(iss_payload, hmac_secret, 'HS256')

      expect do
        # Add iss to the validation to check if the token has been manipulated
        JWT.decode(token, nil, true, { iss: issuers, verify_iss: true, algorithm: 'HS256' }) do |_header, payload|
          secrets[payload['iss']]
        end
      end.not_to raise_error
    end

    context 'The JWK based encode/decode routine' do
      it 'works as expected' do
        # ---------- ENCODE ----------
        optional_parameters = { kid: 'my-kid', use: 'sig', alg: 'RS512' }
        jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), optional_parameters)

        # Encoding
        payload = { data: 'test' }
        token = JWT.encode(payload, jwk.signing_key, jwk[:alg], { kid: jwk[:kid] })

        # JSON Web Key Set for advertising your signing keys
        jwks_hash = JWT::JWK::Set.new(jwk).export

        # ---------- DECODE ----------
        jwks = JWT::JWK::Set.new(jwks_hash)
        jwks.select! { |key| key[:use] == 'sig' } # Signing keys only
        algorithms = jwks.map { |key| key[:alg] }.compact.uniq
        decoded_token = JWT.decode(token, nil, true, { algorithms: algorithms, jwks: jwks })

        expect(decoded_token.first).to eq('data' => 'test')
      end
    end

    context 'The JWKS loader example' do
      let(:logger_output) { StringIO.new }
      let(:logger) { Logger.new(logger_output) }

      it 'works as expected (legacy)' do
        jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), 'optional-kid')
        payload = { data: 'test' }
        headers = { kid: jwk.kid }

        token = JWT.encode(payload, jwk.signing_key, 'RS512', headers)

        # The jwk loader would fetch the set of JWKs from a trusted source,
        # to avoid malicious invalidations some kind of protection needs to be implemented.
        # This example only allows cache invalidations every 5 minutes.
        jwk_loader = lambda do |options|
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
        rescue JWT::TokenError
          # Handle other token related issues e.g. no kid in header, no matching public key found etc.
        end

        ## This is not in the example but verifies that the cache is invalidated after 5 minutes
        jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), 'new-kid')

        headers = { kid: jwk.kid }

        token = JWT.encode(payload, jwk.signing_key, 'RS512', headers)
        @cache_last_update = Time.now.to_i - 301

        JWT.decode(token, nil, true, { algorithms: ['RS512'], jwks: jwk_loader })
        expect(logger_output.string.chomp).to match(/^I, .* : Invalidating JWK cache. new-kid not found from previous cache/)

        jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), 'yet-another-new-kid')
        headers = { kid: jwk.kid }
        token = JWT.encode(payload, jwk.signing_key, 'RS512', headers)
        expect { JWT.decode(token, nil, true, { algorithms: ['RS512'], jwks: jwk_loader }) }.to raise_error(JWT::SignatureError, 'Could not find public key for kid yet-another-new-kid')
      end

      it 'works as expected' do
        jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), use: 'sig')
        jwks_hash = JWT::JWK::Set.new(jwk)
        payload = { data: 'test' }
        headers = { kid: jwk.kid }

        token = JWT.encode(payload, jwk.signing_key, 'RS512', headers)

        jwks_loader = lambda do |options|
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
            jwks.select! { |key| key[:use] == 'sig' } # Signing keys only
            jwks
          end
        end

        begin
          JWT.decode(token, nil, true, { algorithms: ['RS512'], jwks: jwks_loader })
        rescue JWT::JWKError
          # Handle problems with the provided JWKs
        rescue JWT::TokenError
          # Handle other token related issues e.g. no kid in header, no matching public key found etc.
        end
      end
    end

    it 'JWK import and export' do
      # Import a JWK Hash (showing an HMAC example, `k` is the base64url-encoded secret)
      hmac_jwk = JWT::JWK.new({ kty: 'oct', k: 'bXkkZWNyZXRLM3k', kid: 'my-kid' })
      expect(hmac_jwk.signing_key).to eq(hmac_secret)

      # Import an OpenSSL key
      # You can optionally add descriptive parameters to the JWK
      desc_params = { kid: 'my-kid', use: 'sig' }
      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), desc_params)

      # Export as JWK Hash (public key only by default)
      _jwk_hash = jwk.export
      _jwk_hash_with_private_key = jwk.export(include_private: true)

      # Export as OpenSSL key
      _public_key = jwk.verify_key
      _private_key = jwk.signing_key if jwk.private?

      # You can also import and export entire JSON Web Key Sets
      jwks_hash = { keys: [{ kty: 'oct', k: 'bXkkZWNyZXRLM3k', kid: 'my-kid' }] }
      jwks = JWT::JWK::Set.new(jwks_hash)
      expect(jwks.export).to eq(keys: [{ kty: 'oct', kid: 'my-kid' }])
    end

    it 'JWK with thumbprint as kid via symbol' do
      JWT.configuration.jwk.kid_generator_type = :rfc7638_thumbprint

      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048))

      jwk_hash = jwk.export

      expect(jwk_hash[:kid].size).to eq(43)
    end

    it 'JWK with thumbprint as kid via type' do
      JWT.configuration.jwk.kid_generator = JWT::JWK::Thumbprint

      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048))

      jwk_hash = jwk.export

      expect(jwk_hash[:kid].size).to eq(43)
    end

    it 'JWK with thumbprint given in the initializer (legacy)' do
      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), kid_generator: JWT::JWK::Thumbprint)

      jwk_hash = jwk.export

      expect(jwk_hash[:kid].size).to eq(43)
    end

    it 'JWK with thumbprint given in the initializer' do
      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), nil, kid_generator: JWT::JWK::Thumbprint)

      jwk_hash = jwk.export

      expect(jwk_hash[:kid].size).to eq(43)
    end
  end
end
