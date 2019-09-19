# frozen_string_literal: true

require_relative '../spec_helper'
require 'jwt'

describe JWT::X509::Validator do
  describe '.valid? for x509 usecase' do
    let(:x5c_valid)             { JSON.load(File.read(File.join(X509_PATH, 'x5c_valid.json')))['x5c'] }
    let(:x5c_no_chain_valid)    { JSON.load(File.read(File.join(X509_PATH, 'x5c_no_chain_valid.json')))['x5c'] }
    let(:x5c_invalid)           { JSON.load(File.read(File.join(X509_PATH, 'x5c_invalid.json')))['x5c'] }

    context 'when the cert has a cert chain' do
      context 'when the cert has been signed by the chain' do
        it 'validates the cert' do
          v = described_class.new(x5c: x5c_valid)
          expect(v.valid?).to be true
        end
      end

      context 'when the cert has not been signed by the chain' do
        it 'invalidates the cert' do
          v = described_class.new(x5c: x5c_invalid)
          expect(v.valid?).to be false
        end
      end
    end

    context 'when the cert has no cert chain' do
      it 'validates the cert' do
        v = described_class.new(x5c: x5c_no_chain_valid)
        expect(v.valid?).to be true
      end
    end

  end
end
