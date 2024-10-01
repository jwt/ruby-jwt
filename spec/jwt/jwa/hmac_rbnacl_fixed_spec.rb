# frozen_string_literal: true

RSpec.describe 'JWT::JWA::HmacRbNaClFixed' do
  subject(:instance) { JWT::JWA::HmacRbNaClFixed.new('HS512256', RbNaCl::HMAC::SHA512256) }
  let(:data) { 'test' }

  before do
    skip('Requires the rbnacl gem') unless JWT.rbnacl? && !JWT.rbnacl_6_or_greater?
  end

  describe '#sign' do
    subject(:sign) { instance.sign(data: data, signing_key: signing_key) }

    let(:signing_key) { '*' * (RbNaCl::HMAC::SHA512256.key_bytes - 1) }

    it { is_expected.not_to be_empty }

    context 'when signing_key key is larger than hmac key bytes' do
      let(:signing_key) { '*' * (RbNaCl::HMAC::SHA512256.key_bytes + 1) }

      it 'raises length error' do
        expect { sign }.to raise_error(RbNaCl::LengthError, a_string_including('key was 33 bytes (Expected 32)'))
      end
    end
  end

  describe '#verify' do
    subject(:verify) { instance.verify(data: data, signature: signature, verification_key: verification_key) }

    let(:signature) { instance.sign(data: data, signing_key: signing_key) }

    let(:verification_key) { '*' * (RbNaCl::HMAC::SHA512256.key_bytes - 1) }
    let(:signing_key) { verification_key }

    it { is_expected.to be(true) }

    context 'when verification_key key is larger than hmac key bytes' do
      let(:verification_key) { '*' * (RbNaCl::HMAC::SHA512256.key_bytes + 1) }
      let(:signature) { 'a_signature' }

      it { is_expected.to be(false) }
    end
  end

  context 'backwards compatibility' do
    it 'signs and verifies' do
      signature = JWT::JWA::HmacRbNaClFixed.sign('HS512256', 'data', 'key')
      expect(JWT::JWA::HmacRbNaClFixed.verify('HS512256', 'key', 'data', signature)).to be(true)
    end
  end
end
