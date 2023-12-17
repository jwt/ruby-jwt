# frozen_string_literal: true

RSpec.describe JWT::JWA::Hmac do
  describe '.sign' do
    subject { described_class.sign('HS256', 'test', hmac_secret) }

    # Address OpenSSL 3.0 errors with empty hmac_secret - https://github.com/jwt/ruby-jwt/issues/526
    context 'when nil hmac_secret is passed' do
      let(:hmac_secret) { nil }
      context 'when OpenSSL 3.0 raises a malloc failure' do
        before do
          allow(OpenSSL::HMAC).to receive(:digest).and_raise(OpenSSL::HMACError.new('EVP_PKEY_new_mac_key: malloc failure'))
        end

        it 'raises JWT::DecodeError' do
          expect { subject }.to raise_error(JWT::DecodeError, 'OpenSSL 3.0 does not support nil or empty hmac_secret')
        end
      end

      context 'when OpenSSL raises any other error' do
        before do
          allow(OpenSSL::HMAC).to receive(:digest).and_raise(OpenSSL::HMACError.new('Another Random Error'))
        end

        it 'raises the original error' do
          expect { subject }.to raise_error(OpenSSL::HMACError, 'Another Random Error')
        end
      end

      context 'when other versions of openssl do not raise an exception' do
        let(:response) { Base64.decode64("Q7DO+ZJl+eNMEOqdNQGSbSezn1fG1nRWHYuiNueoGfs=\n") }
        before do
          allow(OpenSSL::HMAC).to receive(:digest).and_return(response)
        end

        it { is_expected.to eql(response) }
      end
    end

    context 'when blank hmac_secret is passed' do
      let(:hmac_secret) { '' }
      context 'when OpenSSL 3.0 raises a malloc failure' do
        before do
          allow(OpenSSL::HMAC).to receive(:digest).and_raise(OpenSSL::HMACError.new('EVP_PKEY_new_mac_key: malloc failure'))
        end

        it 'raises JWT::DecodeError' do
          expect { subject }.to raise_error(JWT::DecodeError, 'OpenSSL 3.0 does not support nil or empty hmac_secret')
        end
      end

      context 'when OpenSSL raises any other error' do
        before do
          allow(OpenSSL::HMAC).to receive(:digest).and_raise(OpenSSL::HMACError.new('Another Random Error'))
        end

        it 'raises the original error' do
          expect { subject }.to raise_error(OpenSSL::HMACError, 'Another Random Error')
        end
      end

      context 'when other versions of openssl do not raise an exception' do
        let(:response) { Base64.decode64("Q7DO+ZJl+eNMEOqdNQGSbSezn1fG1nRWHYuiNueoGfs=\n") }
        before do
          allow(OpenSSL::HMAC).to receive(:digest).and_return(response)
        end

        it { is_expected.to eql(response) }
      end
    end

    context 'when hmac_secret is passed' do
      let(:hmac_secret) { 'test' }
      context 'when OpenSSL 3.0 raises a malloc failure' do
        before do
          allow(OpenSSL::HMAC).to receive(:digest).and_raise(OpenSSL::HMACError.new('EVP_PKEY_new_mac_key: malloc failure'))
        end

        it 'raises the original error' do
          expect { subject }.to raise_error(OpenSSL::HMACError, 'EVP_PKEY_new_mac_key: malloc failure')
        end
      end

      context 'when OpenSSL raises any other error' do
        before do
          allow(OpenSSL::HMAC).to receive(:digest).and_raise(OpenSSL::HMACError.new('Another Random Error'))
        end

        it 'raises the original error' do
          expect { subject }.to raise_error(OpenSSL::HMACError, 'Another Random Error')
        end
      end

      context 'when other versions of openssl do not raise an exception' do
        let(:response) { Base64.decode64("iM0hCLU0fZc885zfkFPX3UJwSHbYyam9ji0WglnT3fc=\n") }
        before do
          allow(OpenSSL::HMAC).to receive(:digest).and_return(response)
        end

        it { is_expected.to eql(response) }
      end
    end
  end
end
