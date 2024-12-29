# frozen_string_literal: true

RSpec.describe JWT::JWA::None do
  subject { described_class.new }

  describe '#sign' do
    it 'returns an empty string' do
      expect(subject.sign('data', 'key')).to eq('')
    end
  end

  describe '#verify' do
    it 'returns true' do
      expect(subject.verify('data', 'signature', 'key')).to be true
    end
  end
end
