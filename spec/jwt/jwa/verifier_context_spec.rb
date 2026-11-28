# frozen_string_literal: true

RSpec.describe JWT::JWA::VerifierContext do
  let(:data) { 'header.payload' }

  subject(:verify) { described_class.new(jwa: jwa, keys: keys).verify(data: data, signature: signature) }

  context 'with HMAC' do
    let(:hmac_secret) { 'a-shared-hmac-secret' }
    let(:jwa) { JWT::JWA.resolve('HS256') }
    let(:signature) { jwa.sign(data: data, signing_key: hmac_secret) }
    let(:ec_key) { test_pkey('ec256-private.pem') }

    context 'when a key of the wrong type comes before the right key' do
      let(:keys) { [ec_key, hmac_secret] }

      it { is_expected.to be(true) }
    end

    context 'when a key of the wrong type comes after the right key' do
      let(:keys) { [hmac_secret, ec_key] }

      it { is_expected.to be(true) }
    end

    context 'when a key of the wrong type comes before a key that does not match' do
      let(:keys) { [ec_key, 'not-the-secret'] }

      it 'raises the error for the key of the wrong type' do
        expect { verify }.to raise_error(JWT::VerificationKeyError, 'HMAC key expected to be a String')
      end
    end

    context 'when a key that does not match comes before a key of the wrong type' do
      let(:keys) { ['not-the-secret', ec_key] }

      it 'raises the error for the key of the wrong type' do
        expect { verify }.to raise_error(JWT::VerificationKeyError, 'HMAC key expected to be a String')
      end
    end

    context 'when the only key is of the wrong type' do
      let(:keys) { [ec_key] }

      it 'raises the error for that key' do
        expect { verify }.to raise_error(JWT::VerificationKeyError, 'HMAC key expected to be a String')
      end
    end

    context 'when every key is of the wrong type' do
      let(:keys) { [ec_key, 42] }

      it 'raises the error for the first key' do
        expect { verify }.to raise_error(JWT::VerificationKeyError, 'HMAC key expected to be a String')
      end
    end

    context 'when the keys fail with different errors' do
      let(:keys) { [ec_key, ''] }

      it 'raises the error for the first key' do
        expect { verify }.to raise_error(JWT::VerificationKeyError, 'HMAC key expected to be a String')
      end
    end

    context 'when the keys fail with different errors in the other order' do
      let(:keys) { ['', ec_key] }

      it 'raises the error for the first key' do
        expect { verify }.to raise_error(JWT::VerificationKeyError, 'HMAC key cannot be empty')
      end
    end

    context 'when no key matches' do
      let(:keys) { %w[not-the-secret not-the-secret-either] }

      it { is_expected.to be(false) }
    end

    context 'when no keys are given' do
      let(:keys) { [] }

      it { is_expected.to be(false) }
    end
  end

  context 'with ECDSA keys on different curves' do
    let(:jwa) { JWT::JWA.resolve('ES384') }
    let(:signature) { jwa.sign(data: data, signing_key: test_pkey('ec384-private.pem')) }

    context 'when a key on another curve comes before the right key' do
      let(:keys) { [test_pkey('ec256-public.pem'), test_pkey('ec384-public.pem')] }

      it { is_expected.to be(true) }
    end

    context 'when the only key is on another curve' do
      let(:keys) { [test_pkey('ec256-public.pem')] }

      it 'raises the error for that key' do
        expect { verify }.to raise_error(JWT::IncorrectAlgorithm, 'payload algorithm is ES384 but ES256 verification key was provided')
      end
    end
  end

  context 'with an algorithm that raises for some keys' do
    let(:jwa) do
      Class.new do
        def verify(data:, signature:, verification_key:)
          error_class = error_for(verification_key)
          raise error_class, "raised for #{verification_key}" if error_class

          data == 'header.payload' && signature == 'signature' && verification_key == :right
        end

        def error_for(key)
          {
            verification_error: JWT::VerificationError,
            signature_error: JWT::SignatureError,
            malformed_token_error: JWT::MalformedTokenError,
            argument_error: ArgumentError
          }[key]
        end
      end.new
    end
    let(:signature) { 'signature' }

    context 'when a key raises JWT::VerificationError and a later key matches' do
      let(:keys) { %i[verification_error right] }

      it { is_expected.to be(true) }
    end

    context 'when a key raises JWT::VerificationError and no key matches' do
      let(:keys) { %i[verification_error wrong] }

      it 'raises the error' do
        expect { verify }.to raise_error(JWT::VerificationError, 'raised for verification_error')
      end
    end

    {
      signature_error: JWT::SignatureError,
      malformed_token_error: JWT::MalformedTokenError,
      argument_error: ArgumentError
    }.each do |key, error_class|
      context "when a key raises #{error_class} and a later key matches" do
        let(:keys) { [key, :right] }

        it 'raises the error without trying the later key' do
          expect { verify }.to raise_error(error_class, "raised for #{key}")
        end
      end
    end
  end
end
