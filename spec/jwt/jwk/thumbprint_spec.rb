# frozen_string_literal: true

describe JWT::JWK::Thumbprint do
  describe '#to_s' do
    let(:jwk_json) { nil }
    let(:jwk)      { JWT::JWK.import(JSON.parse(jwk_json)) }

    subject(:thumbprint) { described_class.new(jwk).to_s }

    context 'when example from RFC is given' do
      let(:jwk_json) {
        '
        {
           "kty": "RSA",
           "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt' \
                'VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6' \
                '4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD' \
                'W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9' \
                '1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH' \
                'aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
           "e": "AQAB",
           "alg": "RS256"
        }
        '
      }

      it { is_expected.to eq('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs') }
    end

    context 'when HMAC key is given' do
      let(:jwk_json) {
        '
        {
          "kty":"oct",
          "alg":"HS512",
          "k":"B4uZ7IbZTnjdCQjUBXTpzMUznCYj3wdYDZcceeU0mLg"
        }
        '
      }

      it { is_expected.to eq('wPf4ZF5qlzoFxsGkft4eu1iWcehgAcahZL4XPV4dT-s') }
    end

    context 'when EC key is given' do
      let(:jwk_json) do
        '
        {
          "kty":"EC",
          "crv":"P-384",
          "x":"sbOnPOXPBULpeizfstr8b6b31QmvEnChXJNYBhXlmpGbs3vZtomBxNORYTT9Wylq",
          "y":"mfyY4VJDbdKGVjBSIhN9BJEq--6IPuKy3gbIr734n6Xd81lnvKslPwjB-sdGouD6"
        }
        '
      end

      it { is_expected.to eq('dO52_we59sdR49HsGCpVzlDUQNvT3KxCTGakk4Un8qc') }
    end
  end
end
