# frozen_string_literal: true

RSpec.describe JWT::JWK::EC do
  let(:ec_key) { OpenSSL::PKey::EC.generate('secp384r1') }

  describe '.new' do
    subject { described_class.new(keypair) }

    context 'when a keypair with both keys given' do
      let(:keypair) { ec_key }
      it 'creates an instance of the class' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq true
      end
    end

    context 'when a keypair with only public key is given' do
      let(:keypair) { OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec256-public.pem'))) }
      it 'creates an instance of the class' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq false
      end
    end
  end

  describe '#export' do
    let(:kid) { nil }
    subject { described_class.new(keypair, kid).export }

    context 'when keypair with private key is exported' do
      let(:keypair) { ec_key }
      it 'returns a hash with the both parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :kid, :x, :y)

        # Exported keys do not currently include private key info,
        # event if the in-memory key had that information.  This is
        # done to match the traditional behavior of RSA JWKs.
        ## expect(subject).to include(:d)
      end
    end

    context 'when keypair with public key is exported' do
      let(:keypair) { OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec256-public.pem'))) }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :kid, :x, :y)

        # Don't include private `d` if not explicitly requested.
        expect(subject).not_to include(:d)
      end

      context 'when a custom "kid" is provided' do
        let(:kid) { 'custom_key_identifier' }
        it 'exports it' do
          expect(subject[:kid]).to eq 'custom_key_identifier'
        end
      end
    end

    context 'when private key is requested' do
      subject { described_class.new(keypair).export(include_private: true) }
      let(:keypair) { ec_key }
      it 'returns a hash with the both parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :kid, :x, :y)

        # `d` is the private part.
        expect(subject).to include(:d)
      end
    end

    context 'when a common parameter is given' do
      let(:parameters) { { use: 'sig' } }
      let(:keypair) { ec_key }
      subject { described_class.new(keypair, parameters).export }
      it 'returns a hash including the common parameter' do
        expect(subject).to include(:use)
      end
    end
  end

  describe '.import' do
    subject { described_class.import(params) }
    let(:include_private) { false }
    let(:exported_key) { described_class.new(keypair).export(include_private: include_private) }

    ['P-256', 'P-384', 'P-521', 'P-256K'].each do |crv|
      context "when crv=#{crv}" do
        let(:openssl_curve) { JWT::JWK::EC.to_openssl_curve(crv) }
        let(:ec_key) { OpenSSL::PKey::EC.generate(openssl_curve) }

        context 'when keypair is private' do
          let(:include_private) { true }
          let(:keypair) { ec_key }
          let(:params) { exported_key }

          it 'returns a private key' do
            expect(subject.private?).to eq true
            expect(subject).to be_a described_class

            # Regular export returns only the non-private parts.
            public_only = exported_key.reject { |k, _v| k == :d }
            expect(subject.export).to eq(public_only)

            # Private export returns the original input.
            expect(subject.export(include_private: true)).to eq(exported_key)
          end

          context 'with a custom "kid" value' do
            let(:exported_key) {
              super().merge(kid: 'custom_key_identifier')
            }
            it 'imports that "kid" value' do
              expect(subject.kid).to eq('custom_key_identifier')
            end
          end
        end

        context 'when keypair is public' do
          context 'returns a public key' do
            let(:keypair) { OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec256-public.pem'))) }
            let(:params) { exported_key }

            it 'returns a hash with the public parts of the key' do
              expect(subject).to be_a described_class
              expect(subject.private?).to eq false
              expect(subject.export).to eq(exported_key)
            end
          end
        end
      end
    end
  end
end
