# frozen_string_literal: true

require_relative '../spec_helper'
require 'jwt'

describe JWT::JWK::HMAC do
  let(:hmac_key) { 'secret-key' }

  describe '.new' do
    subject { described_class.new(key) }

    context 'when a secret key given' do
      let(:key) { hmac_key }
      it 'creates an instance of the class' do
        expect(subject).to be_a described_class
        expect(subject.private?).to eq true
      end
    end
  end

  describe '#export' do
    let(:kid) { nil }
    subject { described_class.new(key, kid).export }

    context 'when key is exported' do
      let(:key) { hmac_key }
      it 'returns a hash with the key' do
        expect(subject).to be_a Hash
        expect(subject).to include(:kty, :kid, :k)
      end
    end
  end

  describe '.import' do
    subject { described_class.import(params) }
    let(:exported_key) { described_class.new(key).export }

    context 'when secret key is given' do
      let(:key) { hmac_key }
      let(:params) { exported_key }

      it 'returns a key' do
        expect(subject).to be_a described_class
        expect(subject.export).to eq(exported_key)
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
  end
end
