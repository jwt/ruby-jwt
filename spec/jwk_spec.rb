# frozen_string_literal: true

require 'spec_helper'
require 'jwt'

describe JWT::JWK do
  let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

  describe '.import' do
    let(:keypair) { rsa_key.public_key }
    let(:params)  { described_class.new(keypair).export }

    subject { described_class.import(params) }

    it 'creates a ::JWT::JWK::RSA instance' do
      expect(subject).to be_a ::JWT::JWK::RSA
      expect(subject.export).to eq(params)
    end

    context 'when keytype is not supported' do
      let(:params) { { kty: 'unsupported' } }

      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError)
      end
    end
  end

  describe '.to_jwk' do
    subject { described_class.new(keypair) }

    context 'when RSA key is given' do
      let(:keypair) { rsa_key }
      it { is_expected.to be_a ::JWT::JWK::RSA }
    end

    context 'when unsupported key is given' do
      let(:keypair) { 'key' }
      it 'raises an error' do
        expect { subject }.to raise_error(::JWT::JWKError, 'Cannot create JWK from a String')
      end
    end
  end
end
