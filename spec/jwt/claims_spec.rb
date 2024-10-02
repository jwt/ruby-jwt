# frozen_string_literal: true

RSpec.describe JWT::Claims do
  let(:payload) { { 'pay' => 'load' } }
  describe '.verify_payload!' do
    context 'when required_claims is passed' do
      it 'raises error' do
        expect { described_class.verify_payload!(payload, required: ['exp']) }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim exp')
      end
    end

    context 'exp claim' do
      let(:payload) { { 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

      it 'verifies the exp' do
        described_class.verify_payload!(payload, required: ['exp'])
        expect { described_class.verify_payload!(payload, exp: {}) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        described_class.verify_payload!(payload, exp: { leeway: 1000 })
      end

      context 'when claims given as symbol' do
        it 'validates the claim' do
          expect { described_class.verify_payload!(payload, :exp) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
      end

      context 'when claims given as a list of symbols' do
        it 'validates the claim' do
          expect { described_class.verify_payload!(payload, :exp, :nbf) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
      end

      context 'when claims given as a list of symbols and hashes' do
        it 'validates the claim' do
          expect { described_class.verify_payload!(payload, { exp: { leeway: 1000 }, nbf: {} }, :exp, :nbf) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
      end
    end
  end

  describe '.valid_payload?' do
    context 'exp claim' do
      let(:payload) { { 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

      context 'when claim is valid' do
        it 'returns true' do
          expect(described_class.valid_payload?(payload, exp: { leeway: 1000 })).to be(true)
        end
      end

      context 'when claim is invalid' do
        it 'returns false' do
          expect(described_class.valid_payload?(payload, :exp)).to be(false)
        end
      end
    end

    context 'various types of params' do
      context 'when payload is missing most of the claims' do
        it 'raises an error' do
          expect do
            described_class.verify_payload!(payload,
                                            :nbf,
                                            iss: ['www.host.com', 'https://other.host.com'].freeze,
                                            aud: 'aud',
                                            exp: { leeway: 10 })
          end.to raise_error(JWT::InvalidIssuerError)
        end
      end

      context 'when payload has everything that is expected of it' do
        let(:payload) { { 'iss' => 'www.host.com', 'aud' => 'audience', 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

        it 'does not raise' do
          expect do
            described_class.verify_payload!(payload,
                                            :nbf,
                                            iss: ['www.host.com', 'https://other.host.com'].freeze,
                                            aud: 'audience',
                                            exp: { leeway: 11 })
          end.not_to raise_error
        end
      end
    end
  end

  describe '.payload_errors' do
    context 'exp claim' do
      let(:payload) { { 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

      context 'when claim is valid' do
        it 'returns empty array' do
          expect(described_class.payload_errors(payload, exp: { leeway: 1000 })).to be_empty
        end
      end

      context 'when claim is invalid' do
        it 'returns array with error objects' do
          expect(described_class.payload_errors(payload, :exp).map(&:message)).to eq(['Signature has expired'])
        end
      end
    end

    context 'various types of params' do
      let(:payload) { { 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

      context 'when payload is most of the claims' do
        it 'raises an error' do
          messages = described_class.payload_errors(payload,
                                                    :nbf,
                                                    iss: ['www.host.com', 'https://other.host.com'].freeze,
                                                    aud: 'aud',
                                                    exp: { leeway: 10 }).map(&:message)
          expect(messages).to eq(['Invalid issuer. Expected ["www.host.com", "https://other.host.com"], received <none>',
                                  'Invalid audience. Expected aud, received <none>',
                                  'Signature has expired'])
        end
      end
    end
  end
end
