# frozen_string_literal: true

RSpec.describe 'JWT::JWA::Eddsa' do
  let(:key) { RbNaCl::Signatures::Ed25519::SigningKey.generate }

  before do
    skip('Requires the rbnacl gem') unless JWT.rbnacl?
  end

  context 'backwards compatibility' do
    it 'signs and verifies' do
      signature = JWT::JWA::Eddsa.sign('RS256', 'data', key)
      expect(JWT::JWA::Eddsa.verify('RS256', key.verify_key, 'data', signature)).to be(true)
    end
  end
end
