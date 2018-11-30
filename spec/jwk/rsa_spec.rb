# frozen_string_literal: true

require_relative '../spec_helper'
require 'jwt'

describe JWT::JWK::RSA do
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

  describe '#export' do
    subject { described_class.new(keypair).export }

    context 'when keypair with private key is exported' do
      let(:keypair) { rsa_key }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :n, :e, :kid)
        expect(subject).not_to include(:d)
      end
    end

    context 'when keypair with public key is exported' do
      let(:keypair) { rsa_key.public_key }
      it 'returns a hash with the public parts of the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :n, :e, :kid)
        expect(subject).not_to include(:d)
      end
    end

    context 'when unsupported keypair is given' do
      let(:keypair) { 'key' }
      it 'raises an error' do
        expect { subject }.to raise_error(ArgumentError, 'keypair must be of type OpenSSL::PKey::RSA')
      end
    end
  end
end
