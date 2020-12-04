# frozen_string_literal: true

require_relative '../spec_helper'
require 'jwt'

describe JWT::JWK::OKP do
  let(:private_key) { RbNaCl::Signatures::Ed25519::SigningKey.new(SecureRandom.hex) }
  let(:public_key)  { private_key.verify_key }

  describe '.new' do
    context 'when private key is given' do
      it 'creates a new instance' do
        expect(described_class.new(private_key)).to be_a(described_class)
      end
    end
    context 'when public key is given' do
      it 'creates a new instance' do
        expect(described_class.new(public_key)).to be_a(described_class)
      end
    end
    context 'when something else than a public or private key is given' do
      it 'raises an ArgumentError' do
        expect { described_class.new(OpenSSL::PKey::RSA.new(2048)) }.to raise_error(ArgumentError)
      end
    end
  end
end if defined?(RbNaCl)
