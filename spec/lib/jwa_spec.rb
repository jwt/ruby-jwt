require 'spec_helper'
require 'jwa'

describe JWA do
  let(:string) { 'My awesome string that works' }
  let(:hash) { { text: 'My awesome hash that should not work.' } }
  let(:secret) { 'TopSecret' }
  let(:wrong_secret) { 'TopWrongSecret' }

  let(:rsa_key) do
    {
        '1024'       => {
            public:  File.read(File.join(CERT_PATH, 'rsa-1024-public.pem')),
            private: File.read(File.join(CERT_PATH, 'rsa-1024-private.pem'))
        },
        '2048'       => {
            public:  File.read(File.join(CERT_PATH, 'rsa-2048-public.pem')),
            private: File.read(File.join(CERT_PATH, 'rsa-2048-private.pem'))
        },
        '2048_wrong' => {
            public:  File.read(File.join(CERT_PATH, 'rsa-2048-wrong-public.pem')),
            private: File.read(File.join(CERT_PATH, 'rsa-2048-wrong-private.pem'))
        },
        '4096'       => {
            public:  File.read(File.join(CERT_PATH, 'rsa-4096-public.pem')),
            private: File.read(File.join(CERT_PATH, 'rsa-4096-private.pem'))
        }
    }
  end

  it 'should only accept registered, case-sensitive algorithms' do
    %w(HS256 HS384 HS512).each do |algo|
      signature = JWA.sign algo, string, secret

      expect { JWA.sign(algo, string, secret) }.not_to raise_error
      expect { JWA.verify(algo, string, signature, secret) }.not_to raise_error
    end

    %w(RS256 RS384 RS512).each do |algo|
      signature = JWA.sign algo, string, rsa_key['2048'][:private]

      expect { JWA.sign(algo, string, rsa_key['2048'][:private]) }.not_to raise_error
      expect { JWA.verify(algo, string, signature, rsa_key['2048'][:public]) }.not_to raise_error
    end

    expect { JWA.sign('RSA1_5', string) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.verify('RS513', string, secret) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.sign('hs256', string) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.verify('NONE', string, secret) }.to raise_error(JWA::InvalidAlgorithm)

    expect(JWA::ALGORITHMS).to eq(%w(HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 none))
  end

  it 'should raise if algorithm is not implemented' do
    %w(ES256 ES384 ES512 PS256 PS384 PS512).each do |algo|
      expect { JWA.sign(algo, string, secret) }.to raise_error(JWA::NotImplemented)
      expect { JWA.verify(algo, string, secret) }.to raise_error(JWA::NotImplemented)
    end
  end

  it 'should only accept strings as input data' do
    algo = 'HS256'
    sign = JWA.sign algo, string, secret

    expect { JWA.sign(algo, hash, secret) }.to raise_error(JWA::InvalidPayloadFormat)
    expect { JWA.sign(algo, string, secret) }.not_to raise_error

    expect { JWA.verify(algo, hash, secret, secret) }.to raise_error(JWA::InvalidPayloadFormat)
    expect { JWA.verify(algo, string, sign, secret) }.not_to raise_error
  end

  context 'using' do
    let(:payload) do
      'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4'
    end

    let(:secret) do
      JWT::Base64.decode 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg'
    end

    let(:hmac_signatures) do
      {
          '256' => 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0',
          '384' => 'O1jhTTHkuaiubwDZoIBLv6zjEarXHc22NNu05IdYh_yzIKGYXJQcaI2WnF4BCq7j',
          '512' => 'rdWYqzXuAJp4OW-exqIwrO8HJJQDYu0_fkTIUBHmyHMFJ0pVe7fjP7QtE7BaX-7FN5YiyiM11MwIEAxzxBj6qw'
      }
    end

    let(:rsa_2048_signatures) do
      {
          '256' => JWA.sign('RS256', payload, rsa_key['2048'][:private]),
          '384' => JWA.sign('RS384', payload, rsa_key['2048'][:private]),
          '512' => JWA.sign('RS512', payload, rsa_key['2048'][:private])
      }
    end

    [256, 384, 512].each do |bits|
      context "sign HMAC SHA-#{bits} (HS#{bits})" do
        let(:algorithm) { "HS#{bits}" }

        it 'should always require a password' do
          expect { JWA.sign(algorithm, payload) }.to raise_error(JWA::MissingSecretOrKey)
          expect { JWA.sign(algorithm, payload, secret) }.not_to raise_error
        end

        it 'should return the correct computed signature as base64 urlsafe string' do
          expect(JWA.sign(algorithm, payload, secret)).to eq(hmac_signatures[bits.to_s])
        end
      end

      context "verify HMAC SHA-#{bits} (HS#{bits})" do
        let(:algorithm) { "HS#{bits}" }

        it 'should always require a password' do
          expect { JWA.verify(algorithm, payload, hmac_signatures[bits.to_s]) }.to raise_error(JWA::MissingSecretOrKey)
          expect { JWA.verify(algorithm, payload, hmac_signatures[bits.to_s], secret) }.not_to raise_error
        end

        it 'should return true for matching signature and data' do
          expect(JWA.verify(algorithm, payload, hmac_signatures[bits.to_s], secret)).to eq(true)
        end
      end
    end

    [256, 384, 512].each do |bits|
      context "sign RSA SHA-#{bits} (RS#{bits})" do
        let(:algorithm) { "RS#{bits}" }

        it 'should always require a rsa key' do
          expect { JWA.sign(algorithm, payload) }.to raise_error(JWA::MissingSecretOrKey)
          expect { JWA.sign(algorithm, payload, rsa_key['2048'][:private]) }.not_to raise_error
        end

        it 'should return the correct computed signature as base64 urlsafe string' do
          expect(JWA.sign(algorithm, payload, rsa_key['2048'][:private])).to eq(rsa_2048_signatures[bits.to_s])
        end
      end

      context "verify RSA SHA-#{bits} (RS#{bits})" do
        let(:algorithm) { "RS#{bits}" }

        it 'should always require a key' do
          expect { JWA.verify(algorithm, payload, rsa_2048_signatures[bits.to_s]) }.to raise_error(JWA::MissingSecretOrKey)
          expect { JWA.verify(algorithm, payload, rsa_2048_signatures[bits.to_s], rsa_key['2048'][:public]) }.not_to raise_error
        end

        it 'should return true for matching signature and data' do
          expect(JWA.verify(algorithm, payload, rsa_2048_signatures[bits.to_s], rsa_key['2048'][:public])).to eq(true)
        end

        it 'should return for mismatching signature and data' do
          expect(JWA.verify(algorithm, payload, rsa_2048_signatures[bits.to_s], rsa_key['2048_wrong'][:public])).to eq(false)
          expect(JWA.verify(algorithm, payload, rsa_2048_signatures[bits.to_s], rsa_key['4096'][:public])).to eq(false)
        end
      end

      it 'should raise if key is weaker than 2048 bits' do
        expect { JWA.sign('RS256', payload, rsa_key['1024'][:private]) }.to raise_error(JWA::RSASSA::KeyStrength)
        expect { JWA.sign('RS256', payload, rsa_key['2048'][:private]) }.not_to raise_error
        expect { JWA.sign('RS256', payload, rsa_key['4096'][:private]) }.not_to raise_error
      end
    end
  end
end
