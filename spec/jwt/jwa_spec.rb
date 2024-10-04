# frozen_string_literal: true

RSpec.describe JWT::JWA do
  describe '.create' do
    describe 'Backwards compatibility' do
      describe 'create, sign and verify' do
        it 'finds an algorithm with old api' do
          alg = described_class.create('HS256')
          signature = alg.sign(data: 'data', signing_key: 'key')
          expect(signature).to be_a(String)
          expect(alg.verify(data: 'data', signature: signature, verification_key: 'key')).to be(true)
        end
      end
    end
  end
  describe '.resolve_and_sort' do
    let(:subject) { described_class.resolve_and_sort(algorithms: algorithms, preferred_algorithm: preferred_algorithm).map(&:alg) }

    context 'when algorithms have the preferred last' do
      let(:algorithms) { %w[HS256 HS512 RS512] }
      let(:preferred_algorithm) { 'RS512' }

      it 'places the preferred algorithm first' do
        is_expected.to eq(%w[RS512 HS256 HS512])
      end
    end

    context 'when algorithms have the preferred in the middle' do
      let(:algorithms) { %w[HS512 HS256 RS512] }
      let(:preferred_algorithm) { 'HS256' }

      it 'places the preferred algorithm first' do
        is_expected.to eq(%w[HS256 HS512 RS512])
      end
    end
  end
end
