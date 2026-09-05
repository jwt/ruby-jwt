# frozen_string_literal: true

RSpec.describe JWT::JWK::Set do
  describe '.new' do
    it 'can create an empty set' do
      expect(described_class.new.keys).to eql([])
    end

    context 'can create a set' do
      it 'from a JWK' do
        jwk = JWT::JWK.new('testkey')
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
        jwk = JWT::JWK.new('testkey')
        expect(described_class.new([jwk]).keys).to eql([jwk])
      end

      it 'from an existing JWT::JWK::Set' do
        jwk = JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') })
        jwks = described_class.new(jwk)
        expect(described_class.new(jwks)).to eql(jwks)
      end
    end

    context 'when created from an existing JWT::JWK::Set' do
      let(:jwk) { JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') }) }
      let(:other) { JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('otherkey') }) }
      let(:original) { described_class.new([jwk]) }
      let(:copy) { described_class.new(original) }

      it 'does not share the key collection with the original' do
        expect(copy.keys).not_to be(original.keys)
      end

      it 'keeps the original intact when keys are added to the copy' do
        copy.add(other)
        expect(original.keys).to eql([jwk])
      end

      it 'keeps the original intact when keys are removed from the copy' do
        copy.delete(jwk)
        expect(original.keys).to eql([jwk])
      end

      it 'keeps the original intact when the copy is filtered' do
        copy.select! { false }
        expect(original.keys).to eql([jwk])
      end

      it 'shares the key objects with the original' do
        expect(copy.keys.first).to be(original.keys.first)
      end
    end

    context 'when duplicated' do
      let(:jwk) { JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') }) }
      let(:other) { JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('otherkey') }) }
      let(:original) { described_class.new([jwk]) }

      it 'does not share the key collection with the original' do
        expect(original.dup.keys).not_to be(original.keys)
      end

      it 'keeps the original intact when keys are added to the duplicate' do
        original.dup << other
        expect(original.keys).to eql([jwk])
      end

      it 'keeps the original intact when the duplicate is filtered' do
        original.dup.reject! { true }
        expect(original.keys).to eql([jwk])
      end
    end

    context 'when a union is built from it' do
      let(:jwk) { JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('testkey') }) }
      let(:other) { JWT::JWK.new({ kty: 'oct', k: Base64.strict_encode64('otherkey') }) }
      let(:original) { described_class.new([jwk]) }

      it 'keeps the original intact' do
        original.union([other])
        expect(original.keys).to eql([jwk])
      end
    end

    it 'ignores keys with unsupported kty values (RFC 7517 §5), required for hybrid PQC' do
      jwks = {
        keys: [
          { kty: 'unknown', alg: 'unknown-alg', kid: 'unknown' },
          { kty: 'oct', k: Base64.strict_encode64('testkey') }
        ]
      }
      set = described_class.new(jwks)
      expect(set.size).to eql(1)
      expect(set.keys[0][:kty]).to eql('oct')
    end

    it 'returns an empty set when all keys have unsupported kty values' do
      jwks = {
        keys: [
          { kty: 'unknown', alg: 'unknown-alg', kid: 'unknown-1' },
          { kty: 'future', alg: 'future-alg', kid: 'future-1' }
        ]
      }
      set = described_class.new(jwks)
      expect(set.size).to eql(0)
    end

    it 'raises on malformed keys with a known kty' do
      jwks = {
        keys: [
          { kty: 'RSA' }
        ]
      }
      expect { described_class.new(jwks) }.to raise_error(JWT::JWKError, /Key format is invalid for RSA/)
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
