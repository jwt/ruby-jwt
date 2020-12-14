# frozen_string_literal: true

describe JWT::JWK::Thumbprint do
  describe '#to_s' do
    context 'when example from RFC is given' do
      let(:rfc_example) {
        '{ "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt' \
              'VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6' \
              '4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD' \
              'W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9' \
              '1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH' \
              'aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29" }'
      }

      let(:jwk) { JWT::JWK.import(JSON.parse(rfc_example)) }

      it 'calculates the correct thumbprint' do
        expect(described_class.new(jwk).to_s).to eq('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs')
      end
    end
    context 'when HMAC key is given' do
      let(:hmac_key) {
        '
        {
          "kty":"oct",
          "kid":"wPf4ZF5qlzoFxsGkft4eu1iWcehgAcahZL4XPV4dT-s",
          "alg":"HS512",
          "k":"B4uZ7IbZTnjdCQjUBXTpzMUznCYj3wdYDZcceeU0mLg"
        }
        '
      }

      let(:jwk) { JWT::JWK.import(JSON.parse(hmac_key)) }

      it 'calculates the correct thumbprint' do
        expect(described_class.new(jwk).to_s).to eq('wPf4ZF5qlzoFxsGkft4eu1iWcehgAcahZL4XPV4dT-s')
      end
    end
  end
end
