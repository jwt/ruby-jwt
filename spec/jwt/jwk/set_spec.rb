# frozen_string_literal: true

RSpec.describe JWT::JWK::Set do
  describe '.new' do
    it 'can create an empty set' do
      expect(described_class.new.keys).to eql([])
    end

    context 'can create a set' do
      it 'from a JWK' do
        jwk = JWT::JWK.new 'testkey'
        expect(described_class.new(jwk).keys).to eql([jwk])
      end

      it 'from a JWKS hash with symbol keys' do
        jwks = { keys: [{ kty: 'oct', k: Base64.strict_encode64('testkey') }] }
        jwk = JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') })
        expect(described_class.new(jwks).keys).to eql([jwk])
      end

      it 'from a JWKS hash with string keys' do
        jwks = { 'keys' => [{ 'kty' => 'oct', 'k' => Base64.strict_encode64('testkey') }] }
        jwk = JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') })
        expect(described_class.new(jwks).keys).to eql([jwk])
      end

      it 'from an array of keys' do
        jwk = JWT::JWK.new 'testkey'
        expect(described_class.new([jwk]).keys).to eql([jwk])
      end

      it 'from an existing JWT::JWK::Set' do
        jwk = JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') })
        jwks = described_class.new(jwk)
        expect(described_class.new(jwks)).to eql(jwks)
      end
    end

    it 'raises an error on invalid inputs' do
      expect { described_class.new(42) }.to raise_error(ArgumentError)
    end
  end

  describe '.export' do
    it 'exports the JWKS to Hash' do
      jwk = JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') })
      jwks = described_class.new(jwk)
      exported = jwks.export
      expect(exported[:keys].size).to eql(1)
      expect(exported[:keys][0]).to eql(jwk.export)
    end
  end

  describe '.eql?' do
    it 'correctly classifies equal sets' do
      jwk = JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') })
      jwks1 = described_class.new(jwk)
      jwks2 = described_class.new(jwk)
      expect(jwks1).to eql(jwks2)
    end

    it 'correctly classifies different sets' do
      jwk1 = JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') })
      jwk2 = JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkex') })
      jwks1 = described_class.new(jwk1)
      jwks2 = described_class.new(jwk2)
      expect(jwks1).not_to eql(jwks2)
    end
  end

  # TODO: No idea why this does not work. eql? returns true for the two elements,
  #       but Array#uniq! doesn't recognize this, despite the documentation saying otherwise
  describe '.uniq!' do
    it 'filters out equal keys' do
      jwk = JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') })
      jwk2 = JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') })
      jwks = described_class.new([jwk, jwk2])
      jwks.uniq!
      expect(jwks.keys.size).to eql(1)
    end
  end

  describe '.select!' do
    it 'filters the keyset' do
      jwks = described_class.new([])
      jwks << JWT::JWK.new(test_pkey('rsa-2048-private.pem'))
      jwks << JWT::JWK.new(test_pkey('ec384-private.pem'))
      jwks.select! { |k| k[:kty] == 'RSA' }
      expect(jwks.size).to eql(1)
      expect(jwks.keys[0][:kty]).to eql('RSA')
    end
  end

  describe '.reject!' do
    it 'filters the keyset' do
      jwks = described_class.new([])
      jwks << JWT::JWK.new(test_pkey('rsa-2048-private.pem'))
      jwks << JWT::JWK.new(test_pkey('ec384-private.pem'))
      jwks.reject! { |k| k[:kty] == 'RSA' }
      expect(jwks.size).to eql(1)
      expect(jwks.keys[0][:kty]).to eql('EC')
    end
  end

  describe '.merge' do
    context 'merges two JWKSs' do
      it 'when called via .union' do
        jwks1 = described_class.new(JWT::JWK.new(test_pkey('rsa-2048-private.pem')))
        jwks2 = described_class.new(JWT::JWK.new(test_pkey('ec384-private.pem')))
        jwks3 = jwks1.union(jwks2)
        expect(jwks1.size).to eql(1)
        expect(jwks2.size).to eql(1)
        expect(jwks3.size).to eql(2)
        expect(jwks3.keys).to include(jwks1.keys[0])
        expect(jwks3.keys).to include(jwks2.keys[0])
      end

      it 'when called via "|" operator' do
        jwks1 = described_class.new(JWT::JWK.new(test_pkey('rsa-2048-private.pem')))
        jwks2 = described_class.new(JWT::JWK.new(test_pkey('ec384-private.pem')))
        jwks3 = jwks1 | jwks2
        expect(jwks1.size).to eql(1)
        expect(jwks2.size).to eql(1)
        expect(jwks3.size).to eql(2)
        expect(jwks3.keys).to include(jwks1.keys[0])
        expect(jwks3.keys).to include(jwks2.keys[0])
      end

      it 'when called directly' do
        jwks1 = described_class.new(JWT::JWK.new(test_pkey('rsa-2048-private.pem')))
        jwks2 = described_class.new(JWT::JWK.new(test_pkey('ec384-private.pem')))
        jwks3 = jwks1.merge(jwks2)
        expect(jwks1.size).to eql(2)
        expect(jwks2.size).to eql(1)
        expect(jwks3).to eql(jwks1)
        expect(jwks3.keys).to include(jwks2.keys[0])
      end
    end
  end
end
