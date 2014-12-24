require 'spec_helper'
require_relative '../../lib/jwt'

describe JWT do
  context 'RSASSA' do
    %w(RS256 RS384 RS512).each do |algorithm|
      context "[#{algorithm}] when signing a token" do
        it 'should be syntactically valid'
        it 'should validate with public key'
        it 'should throw with invalid public key'
      end
    end
  end

  context 'HMAC' do
    let(:secret) { 'valid-secret' }

    %w(HS256 HS384 HS512).each do |algorithm|
      context "[#{algorithm}] when signing a token" do
        it 'should be syntactically valid'
        it 'should without options'
        it 'should validate with secret'
        it 'should throw with invalid secret'
        it 'should throw with secret and token not signed'
        it 'should throw when verifying null'
        it 'should throw when the payload is not json'
      end
    end
  end

  context 'ECDSA' do
    %w(ES256 ES384 ES512).each do |algorithm|
      context "[#{algorithm}] when signing a token" do
        it 'should be syntactically valid'
        it 'should without options'
        it 'should validate with secret'
        it 'should throw with invalid secret'
        it 'should throw with secret and token not signed'
        it 'should throw when verifying null'
        it 'should throw when the payload is not json'
      end
    end
  end

  context 'none' do

  end

  context 'when signing a token with expiration' do
    it 'should be valid expiration'
    it 'should be invalid'
  end

  context 'when signing a token with audience' do
    it 'should check audience'
    it 'should check audience in array'
    it 'should throw when invalid audience'
    it 'should throw when invalid audience in array'
  end

  context 'when signing a token with array audience' do
    it 'should check audience'
    it 'should check other audience'
    it 'should check audience in array'
    it 'should throw when invalid audience'
    it 'should throw when invalid audience in array'
  end

  context 'when signing a token without audience' do
    it 'should check audience'
    it 'should check audience in array'
  end

  context 'when signing a token with issuer' do
    it 'should check issuer'
    it 'should throw when invalid issuer'
  end

  context 'when signing a token without issuer' do
    it 'should check issuer'
  end

  context 'when verifying a malformed token' do
    it 'should throw'
  end

  context 'when decoding a jwt token with additional parts' do
    it 'should throw'
  end

  context 'when decoding a invalid jwt token' do
    it 'should return nil'
  end

  context 'when decoding a valid jwt token' do
    it 'should return the payload'
  end
end
