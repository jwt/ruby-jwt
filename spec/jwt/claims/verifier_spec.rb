# frozen_string_literal: true

RSpec.describe JWT::Claims::Verifier do
  describe '.verify!' do
    context 'when all claims are given' do
      let(:options) do
        [
          :exp,
          :nbf,
          { iss: 'issuer' },
          :iat,
          :jti,
          { aud: 'aud' },
          :sub,
          :crit,
          { required: [] },
          :numeric
        ]
      end

      it 'verifies all claims' do
        token = SpecSupport::Token.new(payload: { 'iss' => 'issuer', 'jti' => 1, 'aud' => 'aud' }, header: { 'crit' => [] })
        expect(described_class.verify!(token, *options)).to eq(nil)
      end
    end
  end
end
