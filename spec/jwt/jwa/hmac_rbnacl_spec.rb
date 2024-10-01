# frozen_string_literal: true

RSpec.describe 'JWT::JWA::HmacRbNaCl' do
  before do
    skip('Requires the rbnacl gem') unless JWT.rbnacl_6_or_greater?
  end
  context 'backwards compatibility' do
    it 'signs and verifies' do
      signature = JWT::JWA::HmacRbNaCl.sign('HS512256', 'data', 'key')
      expect(JWT::JWA::HmacRbNaCl.verify('HS512256', 'key', 'data', signature)).to be(true)
    end
  end
end
