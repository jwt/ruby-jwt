# frozen_string_literal: true

require_relative '../spec_helper'
require 'jwt'

if defined?(RbNaCl)
  describe JWT::JWK::OKP do
    let(:private_key) { RbNaCl::Signatures::Ed25519::SigningKey.new(SecureRandom.hex) }
    let(:public_key)  { private_key.verify_key }
    let(:key) { nil }

    subject(:instance) { described_class.new(key) }

    describe '.new' do
      context 'when private key is given' do
        let(:key) { private_key }
        it { is_expected.to be_a(described_class) }
      end
      context 'when public key is given' do
        let(:key) { public_key }
        it { is_expected.to be_a(described_class) }
      end
      context 'when something else than a public or private key is given' do
        let(:key) { OpenSSL::PKey::RSA.new(2048) }
        it 'raises an ArgumentError' do
          expect { instance }.to raise_error(ArgumentError)
        end
      end
    end

    describe '#public_key' do
      let(:key) { private_key }
      subject { instance.public_key }
      it 'is the verify key' do
        expect(subject).to be_a(RbNaCl::Signatures::Ed25519::VerifyKey)
      end
    end

    describe '#private?' do
      subject { instance.private? }
      context 'when private key is given' do
        let(:key) { private_key }
        it { is_expected.to eq(true) }
      end
      context 'when public key is given' do
        let(:key) { public_key }
        it { is_expected.to eq(false) }
      end
    end

    describe '#export' do
      let(:options) { { } }
      subject { instance.export(options) }
      context 'when private key is given' do
        let(:key) { private_key }
        it 'exports the public key' do
          expect(subject).to include(crv: 'Ed25519', kty: 'OKP')
          expect(subject.keys).to eq(%i[kty crv x kid])
          expect(subject[:x].size).to eq(43)
          expect(subject[:kid].size).to eq(43)
        end
      end
      context 'when private key is asked for' do
        let(:key) { private_key }
        let(:options) { { include_private: true } }
        it 'exports the private key' do
          expect(subject).to include(crv: 'Ed25519', kty: 'OKP')
          expect(subject.keys).to eq(%i[kty crv x kid d])
          expect(subject[:x].size).to eq(43)
          expect(subject[:d].size).to eq(43)
          expect(subject[:kid].size).to eq(43)
        end
      end
    end
  end
end
