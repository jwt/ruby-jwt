RSpec.shared_context 'JWK Key interface' do
  it { is_expected.to respond_to(:capabilities) }
  it { is_expected.to respond_to(:signing_key) }
  it { is_expected.to respond_to(:verify_key) }
  it { is_expected.to respond_to(:encryption_key) }
  it { is_expected.to respond_to(:decryption_key) }
  it { is_expected.to respond_to(:export) }
  it { is_expected.to respond_to(:kid) }
end
