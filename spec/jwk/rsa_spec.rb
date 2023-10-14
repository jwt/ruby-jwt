# frozen_string_literal: true

RSpec.describe JWT::JWK::RSA do
  let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

  describe '.new' do
    subject { described_class.new(keypair) }

    context 'when a keypair with both keys given' do
      let(:keypair) { rsa_key }
      it 'creates an instance of the class' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq true
      end
    end

    context 'when a keypair with only public key is given' do
      let(:keypair) { rsa_key.public_key }
      it 'creates an instance of the class' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq false
      end
    end
  end

  describe '#keypair' do
    subject(:jwk) { described_class.new(rsa_key) }

    it 'warns to stderr' do
      expect(jwk.keypair).to eq(rsa_key)
    end
  end

  describe '#export' do
    subject { described_class.new(keypair).export }

    context 'when keypair with private key is exported' do
      let(:keypair) { rsa_key }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :n, :e, :kid)
        expect(subject).not_to include(:d, :p, :dp, :dq, :qi)
      end
    end

    context 'when keypair with public key is exported' do
      let(:keypair) { rsa_key.public_key }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :n, :e, :kid)
        expect(subject).not_to include(:d, :p, :dp, :dq, :qi)
      end
    end

    context 'when unsupported keypair is given' do
      let(:keypair) { 'key' }
      it 'raises an error' do
        expect { subject }.to raise_error(ArgumentError)
      end
    end

    context 'when private key is requested' do
      subject { described_class.new(keypair).export(include_private: true) }
      let(:keypair) { rsa_key }
      it 'returns a hash with the public AND private parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :n, :e, :kid, :d, :p, :q, :dp, :dq, :qi)
      end
    end
  end

  describe '.kid' do
    context 'when configuration says to use :rfc7638_thumbprint' do
      before do
        JWT.configuration.jwk.kid_generator_type = :rfc7638_thumbprint
      end

      it 'generates the kid based on the thumbprint' do
        expect(described_class.new(OpenSSL::PKey::RSA.new(2048)).kid.size).to eq(43)
      end
    end

    context 'when kid is given as a String parameter' do
      it 'uses the given kid' do
        expect(described_class.new(OpenSSL::PKey::RSA.new(2048), 'given').kid).to eq('given')
      end
    end

    context 'when kid is given in a hash parameter' do
      it 'uses the given kid' do
        expect(described_class.new(OpenSSL::PKey::RSA.new(2048), kid: 'given').kid).to eq('given')
      end
    end
  end

  describe '.common_parameters' do
    context 'when a common parameters hash is given' do
      it 'imports the common parameter' do
        expect(described_class.new(OpenSSL::PKey::RSA.new(2048), use: 'sig')[:use]).to eq('sig')
      end

      it 'converts string keys to symbol keys' do
        expect(described_class.new(OpenSSL::PKey::RSA.new(2048), { 'use' => 'sig' })[:use]).to eq('sig')
      end
    end
  end

  describe '.import' do
    subject { described_class.import(params) }
    let(:exported_key) { described_class.new(rsa_key).export }

    context 'when keypair is imported with symbol keys' do
      let(:params) { { kty: 'RSA', e: exported_key[:e], n: exported_key[:n] } }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq false
        expect(subject.export).to eq(exported_key)
      end
    end

    context 'when keypair is imported with string keys from JSON' do
      let(:params) { { 'kty' => 'RSA', 'e' => exported_key[:e], 'n' => exported_key[:n] } }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq false
        expect(subject.export).to eq(exported_key)
      end
    end

    context 'when private key is included in the data' do
      let(:exported_key) { described_class.new(rsa_key).export(include_private: true) }
      let(:params) { exported_key }
      it 'creates a complete keypair' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq true
      end
    end

    context 'when jwk_data is given without e and/or n' do
      let(:params) { { kty: 'RSA' } }
      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, 'Key format is invalid for RSA')
      end
    end
  end

  shared_examples 'creating an RSA object from complete JWK parameters' do
    let(:rsa_parameters) { jwk_parameters.transform_values { |value| described_class.decode_open_ssl_bn(value) } }
    let(:all_jwk_parameters) { described_class.new(rsa_key).export(include_private: true) }

    context 'when public parameters (e, n) are given' do
      let(:jwk_parameters) { all_jwk_parameters.slice(:e, :n) }

      it 'creates a valid RSA object representing a public key' do
        expect(subject).to be_a(OpenSSL::PKey::RSA)
        expect(subject.private?).to eq(false)
      end
    end

    context 'when only e, n, d, p and q are given' do
      let(:jwk_parameters) { all_jwk_parameters.slice(:e, :n, :d, :p, :q) }

      it 'raises an error telling all the exponents are required' do
        expect { subject }.to raise_error(JWT::JWKError, 'When one of p, q, dp, dq or qi is given all the other optimization parameters also needs to be defined')
      end
    end

    context 'when all key components n, e, d, p, q, dp, dq, qi are given' do
      let(:jwk_parameters) { all_jwk_parameters.slice(:n, :e, :d, :p, :q, :dp, :dq, :qi) }

      it 'creates a valid RSA object representing a public key' do
        expect(subject).to be_a(OpenSSL::PKey::RSA)
        expect(subject.private?).to eq(true)
      end
    end
  end

  shared_examples 'creating an RSA object from partial JWK parameters' do
    context 'when e, n, d is given' do
      let(:jwk_parameters) { all_jwk_parameters.slice(:e, :n, :d) }

      before do
        skip 'OpenSSL prior to 2.2 does not seem to support partial parameters' if JWT.openssl_version < Gem::Version.new('2.2')
      end

      it 'creates a valid RSA object representing a private key' do
        expect(subject).to be_a(OpenSSL::PKey::RSA)
        expect(subject.private?).to eq(true)
      end

      it 'can be used for encryption and decryption' do
        expect(subject.private_decrypt(subject.public_encrypt('secret'))).to eq('secret')
      end

      it 'can be used for signing and verification' do
        data = 'data_to_sign'
        signature = subject.sign(OpenSSL::Digest.new('SHA512'), data)
        expect(subject.verify(OpenSSL::Digest.new('SHA512'), signature, data)).to eq(true)
      end
    end
  end

  describe '.create_rsa_key_using_der' do
    subject(:rsa) { described_class.create_rsa_key_using_der(rsa_parameters) }

    include_examples 'creating an RSA object from complete JWK parameters'

    context 'when e, n, d is given' do
      let(:jwk_parameters) { all_jwk_parameters.slice(:e, :n, :d) }

      it 'expects all CRT parameters given and raises error' do
        expect { subject }.to raise_error(JWT::JWKError, 'Creating a RSA key with a private key requires the CRT parameters to be defined')
      end
    end
  end

  describe '.create_rsa_key_using_sets' do
    before do
      skip 'OpenSSL without the RSA#set_key method not supported' unless OpenSSL::PKey::RSA.new.respond_to?(:set_key)
      skip 'OpenSSL 3.0 does not allow mutating objects anymore' if JWT.openssl_3?
    end

    subject(:rsa) { described_class.create_rsa_key_using_sets(rsa_parameters) }

    include_examples 'creating an RSA object from complete JWK parameters'
    include_examples 'creating an RSA object from partial JWK parameters'
  end

  describe '.create_rsa_key_using_accessors' do
    before do
      skip 'OpenSSL if RSA#set_key is available there is no accessors anymore' if OpenSSL::PKey::RSA.new.respond_to?(:set_key)
    end

    subject(:rsa) { described_class.create_rsa_key_using_accessors(rsa_parameters) }

    include_examples 'creating an RSA object from complete JWK parameters'
    include_examples 'creating an RSA object from partial JWK parameters'
  end
end
