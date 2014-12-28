require 'spec_helper'
require 'jwa'

describe JWA do
  let(:string) { 'My awesome string that works' }
  let(:hash) { { text: 'My awesome hash that should not work.' } }
  let(:secret) { 'TopSecret' }
  let(:wrong_secret) { 'TopWrongSecret' }

  it 'should only accept registered, case-sensitive algorithms' do
    %w(HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 none).each do |algo|
      expect { JWA.sign(algo, string, secret) }.not_to raise_error
      expect { JWA.verify(algo, string, secret) }.not_to raise_error
    end

    expect { JWA.sign('RSA1_5', string) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.verify('RS513', string) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.sign('hs256', string) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.verify('NONE', string) }.to raise_error(JWA::InvalidAlgorithm)
  end

  it 'should only accepts strings as input data' do
    algo = 'HS256'

    expect { JWA.sign(algo, hash, secret) }.to raise_error(JWA::InvalidPayloadFormat)
    expect { JWA.sign(algo, string, secret) }.not_to raise_error

    expect { JWA.verify(algo, hash, secret) }.to raise_error(JWA::InvalidPayloadFormat)
    expect { JWA.verify(algo, string, secret) }.not_to raise_error
  end

  context 'sign and verify using' do
    let(:payload) { 'A very string-ish payload.' }

    [256, 384, 512].each do |bits|
      context "HMAC SHA-#{bits} (HS#{bits})" do
        it 'should always require a password' do
          expect { JWA.sign("HS#{bits}", payload) }.to raise_error(JWA::MissingSecretOrKey)
          expect { JWA.sign("HS#{bits}", payload, secret) }.not_to raise_error
        end
      end
    end
  end
end
