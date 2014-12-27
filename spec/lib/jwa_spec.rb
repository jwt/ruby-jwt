require 'spec_helper'
require 'jwa'

describe JWA do
  let(:string) { 'My awesome string that works' }
  let(:hash) { { text: 'My awesome hash that should not work.' } }

  it 'should only accept registered, case-sensitive algorithms' do
    %w(HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 none).each do |algo|
      expect { JWA.sign(algo, string) }.not_to raise_error
      expect { JWA.verify(algo, string) }.not_to raise_error
    end

    expect { JWA.sign('RSA1_5', string) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.verify('RS513', string) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.sign('hs256', string) }.to raise_error(JWA::InvalidAlgorithm)
    expect { JWA.verify('NONE', string) }.to raise_error(JWA::InvalidAlgorithm)
  end

  it 'should only accepts strings as input data' do
    algo = 'HS256'

    expect { JWA.sign(algo, hash) }.to raise_error(JWA::InvalidPayloadFormat)
    expect { JWA.sign(algo, string) }.not_to raise_error

    expect { JWA.verify(algo, hash) }.to raise_error(JWA::InvalidPayloadFormat)
    expect { JWA.verify(algo, string) }.not_to raise_error
  end

  context 'sign' do
    [256, 384, 512].each do |bits|
      context "HMAC using SHA-#{bits}" do
      end
    end
  end
end
