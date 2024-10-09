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

  context 'when when signing with invalid RbNaCl::Signatures::Ed25519::SigningKey' do
    it 'raises an error' do
      expect do
        JWT::JWA::Eddsa.sign('RS256', 'data', 'key')
      end.to raise_error(JWT::EncodeError, 'Key given is a String but has to be an RbNaCl::Signatures::Ed25519::SigningKey')
    end
  end

  context 'when when verifying with invalid RbNaCl::Signatures::Ed25519::VerifyKey' do
    it 'raises an error' do
      expect do
        JWT::JWA::Eddsa.verify('RS256', 'key', 'data', 'signature')
      end.to raise_error(JWT::DecodeError, 'key given is a String but has to be a RbNaCl::Signatures::Ed25519::VerifyKey')
    end
  end
end
