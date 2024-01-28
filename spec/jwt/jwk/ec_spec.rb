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
      let(:keypair) { test_pkey('ec256-public.pem') }
      it 'creates an instance of the class' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq false
      end
    end
  end

  describe '#keypair' do
    subject(:jwk) { described_class.new(ec_key) }

    it 'warns to stderr' do
      expect(jwk.keypair).to eq(ec_key)
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
      let(:keypair) { test_pkey('ec256-public.pem') }
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
            let(:keypair) { test_pkey('ec256-public.pem') }
            let(:params) { exported_key }

            it 'returns a hash with the public parts of the key' do
              expect(subject).to be_a described_class
              expect(subject.private?).to eq false
              expect(subject.export).to eq(exported_key)
            end
          end
        end
      end

      context 'with missing 0-byte at the start of EC coordinates' do
        let(:example_keysets) do
          [
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"0Nv5IKAlkvXuAKmOmFgmrwXKR7qGePOzu_7RXg5msw\",\"y\":\"FqnPSNutcjfvXNlufwb7nLJuUEnBkbMdZ3P79nY9c3k\"}",
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"xGjPg-7meZamM_yfkGeBUB2eJ5c82Y8vQdXwi5cVGw\",\"y\":\"9FwKAuJacVyEy71yoVn1u1ETsQoiwF7QfkfXURGxg14\"}",
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"yTvy0bwt5s29mIg1DMq-IjZH4pDgZIN9keEEaSuWZhk\",\"y\":\"a0nrmd8qz8jpZDgpY82Rgv3vZ5xiJuiAoMIuRlGnaw\"}",
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"yJen7AW4lLUTMH4luDj0wlMNSGCuOBB5R-ZoxlAU_g\",\"y\":\"aMbA-M6ORHePSatiPVz_Pzu7z2XRnKMzK-HIscpfud8\"}",
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"p_D00Z1ydC7mBIpSKPUUrzVzY9Fr5NMhhGfnf4P9guw\",\"y\":\"lCqM3B_s04uhm7_91oycBvoWzuQWJCbMoZc46uqHXA\"}",
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"hKS-vxV1bvfZ2xOuHv6Qt3lmHIiArTnhWac31kXw3w\",\"y\":\"f_UWjrTpmq_oTdfss7YJ-9dEiYw_JC90kwAE-y0Yu-w\"}",
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"3W22hN16OJN1XPpUQuCxtwoBRlf-wGyBNIihQiTmSdI\",\"y\":\"eUaveaPQ4CpyfY7sfCqEF1DCOoxHdMpPHW15BmUF0w\"}",
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"oq_00cGL3SxUZTA-JvcXALhfQya7elFuC7jcJScN7Bs\",\"y\":\"1nNPIinv_gQiwStfx7vqs7Vt_MSyzoQDy9sCnZlFfg\"}",
            "{\"crv\":\"P-521\",\"kty\":\"EC\",\"x\":\"AMNQr/q+YGv4GfkEjrXH2N0+hnGes4cCqahJlV39m3aJpqSK+uiAvkRE5SDm2bZBc3YHGzhDzfMTUpnvXwjugUQP\",\"y\":\"fIwouWsnp44Fjh2gBmO8ZafnpXZwLOCoaT5itu/Q4Z6j3duRfqmDsqyxZueDA3Gaac2LkbWGplT7mg4j7vCuGsw=\"}"
          ]
        end

        it 'prepends a 0-byte so that the keys parse correctly' do
          example_keysets.each do |keyset_json|
            keypair = described_class.import(JSON.parse(keyset_json))
          end
        end
      end
    end
  end
end
