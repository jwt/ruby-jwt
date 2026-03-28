# frozen_string_literal: true

RSpec.describe JWT::JWA::Hmac do
  let(:instance) { described_class.new('HS256', OpenSSL::Digest::SHA256) }
  let(:valid_signature) { [60, 56, 87, 72, 185, 194, 150, 13, 18, 148, 76, 245, 94, 91, 201, 64, 111, 91, 167, 156, 43, 148, 41, 113, 168, 156, 137, 12, 11, 31, 58, 97].pack('C*') }
  let(:hmac_secret) { 'secret_key' }

  describe '#sign' do
    subject { instance.sign(data: 'test', signing_key: hmac_secret) }

    context 'when signing with a key' do
      it { is_expected.to eq(valid_signature) }
    end

    # GHSA-c32j-vqhx-rx3x: empty/nil keys must be rejected before reaching OpenSSL,
    # so a forged token signed with "" cannot verify.
    context 'when nil hmac_secret is passed' do
      let(:hmac_secret) { nil }

      it 'raises JWT::VerificationError' do
        expect { subject }.to raise_error(JWT::VerificationError, 'HMAC key expected to be a String')
      end

      it 'does not call OpenSSL::HMAC.digest' do
        expect(OpenSSL::HMAC).not_to receive(:digest)
        expect { subject }.to raise_error(JWT::DecodeError)
      end
    end

    context 'when blank hmac_secret is passed' do
      let(:hmac_secret) { '' }

      it 'raises JWT::VerificationError' do
        expect { subject }.to raise_error(JWT::VerificationError, 'HMAC key cannot be empty')
      end

      it 'does not call OpenSSL::HMAC.digest' do
        expect(OpenSSL::HMAC).not_to receive(:digest)
        expect { subject }.to raise_error(JWT::DecodeError)
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

    context 'when enforce_hmac_key_length is enabled' do
      before do
        JWT.configuration.decode.enforce_hmac_key_length = true
      end

      after do
        JWT.configuration.decode.enforce_hmac_key_length = false
      end

      context 'when key shorter than algorithm minimum' do
        let(:hmac_secret) { 'short' }

        it 'raises error' do
          expect { subject }.to raise_error(JWT::VerificationError, 'HMAC key must be at least 32 bytes for HS256 algorithm')
        end
      end

      context 'when key meets minimum length' do
        let(:hmac_secret) { 'a' * 32 }

        it 'does not raise error' do
          expect { subject }.not_to raise_error
        end
      end
    end
  end

  describe '#verify' do
    subject { instance.verify(data: 'test', signature: signature, verification_key: hmac_secret) }

    context 'when signature is valid' do
      let(:signature) { valid_signature }

      it { is_expected.to be(true) }
    end

    context 'when signature is invalid' do
      let(:signature) { [60, 56, 87, 72, 185, 194].pack('C*') }

      it { is_expected.to be(false) }
    end

    context 'when verification_key is not a String' do
      let(:signature) { valid_signature }
      let(:hmac_secret) { 123 }

      it 'raises error' do
        expect { subject }.to raise_error(JWT::VerificationError, 'HMAC key expected to be a String')
      end
    end

    # GHSA-c32j-vqhx-rx3x
    context 'when verification_key is nil' do
      let(:signature) { valid_signature }
      let(:hmac_secret) { nil }

      it 'raises error and does not call OpenSSL::HMAC.digest' do
        expect(OpenSSL::HMAC).not_to receive(:digest)
        expect { subject }.to raise_error(JWT::DecodeError, 'HMAC key expected to be a String')
      end
    end

    context 'when verification_key is empty' do
      let(:signature) { valid_signature }
      let(:hmac_secret) { '' }

      it 'raises error and does not call OpenSSL::HMAC.digest' do
        expect(OpenSSL::HMAC).not_to receive(:digest)
        expect { subject }.to raise_error(JWT::DecodeError, 'HMAC key cannot be empty')
      end
    end

    context 'when enforce_hmac_key_length is enabled' do
      before do
        JWT.configuration.decode.enforce_hmac_key_length = true
      end

      after do
        JWT.configuration.decode.enforce_hmac_key_length = false
      end

      let(:signature) { valid_signature }

      context 'when key shorter than algorithm minimum' do
        let(:hmac_secret) { 'short' }

        it 'raises error' do
          expect { subject }.to raise_error(JWT::VerificationError, 'HMAC key must be at least 32 bytes for HS256 algorithm')
        end
      end

      context 'when key meets minimum length' do
        let(:hmac_secret) { 'a' * 32 }

        it 'does not raise error' do
          expect { subject }.not_to raise_error
        end
      end
    end
  end
end
