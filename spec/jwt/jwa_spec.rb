# frozen_string_literal: true

RSpec.describe JWT::JWA do
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
