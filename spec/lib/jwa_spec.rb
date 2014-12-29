require 'spec_helper'
require 'jwa'

describe JWA do
  let(:string) { 'My awesome string that works' }
  let(:hash) { { text: 'My awesome hash that should not work.' } }
  let(:secret) { 'TopSecret' }
  let(:wrong_secret) { 'TopWrongSecret' }

  it 'should only accept registered, case-sensitive algorithms' do
    %w(HS256 HS384 HS512).each do |algo|
      signature = JWA.sign algo, string, secret
      expect { JWA.sign(algo, string, secret) }.not_to raise_error
      expect { JWA.verify(algo, string, signature, secret) }.not_to raise_error
    end

    expect { JWA.sign('RSA1_5', string) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.verify('RS513', string, secret) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.sign('hs256', string) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.verify('NONE', string, secret) }.to raise_error(JWA::InvalidAlgorithm)
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
      Base64.urlsafe_decode64 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg='
    end

    let(:signatures) do
      {
          '256' => 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0',
          '384' => 'O1jhTTHkuaiubwDZoIBLv6zjEarXHc22NNu05IdYh_yzIKGYXJQcaI2WnF4BCq7j',
          '512' => 'rdWYqzXuAJp4OW-exqIwrO8HJJQDYu0_fkTIUBHmyHMFJ0pVe7fjP7QtE7BaX-7FN5YiyiM11MwIEAxzxBj6qw'
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
          expect(JWA.sign(algorithm, payload, secret)).to eq(signatures[bits.to_s])
        end
      end

      context "verify HMAC SHA-#{bits} (HS#{bits})" do
        let(:algorithm) { "HS#{bits}" }

        it 'should always require a password' do
          expect { JWA.verify(algorithm, payload, signatures[bits.to_s]) }.to raise_error(JWA::MissingSecretOrKey)
          expect { JWA.verify(algorithm, payload, signatures[bits.to_s], secret) }.not_to raise_error
        end

        it 'should return true for matching signature and data' do
          expect(JWA.verify(algorithm, payload, signatures[bits.to_s], secret)).to eq(true)
        end
      end
    end
  end
end
