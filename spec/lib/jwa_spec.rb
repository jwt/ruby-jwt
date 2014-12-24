require 'spec_helper'
require_relative '../../lib/jwa'

describe JWA do
  context 'HMAC signing, verifying' do
    [256, 384, 512].each do |bit|
      it "#{bit} should verify"
      it "#{bit} should not verify"
      it 'missing secret'
      it 'weird input'
    end
  end

  context 'RSASSA signing, veryfying' do
    [256, 384, 512].each do |bit|
      it "#{bit} should verify"
      it "#{bit} should not verify"
      it "#{bit} missing sign key"
      it "#{bit} missing verify key"
      it "#{bit} weird input"
    end
  end

  [256, 384, 512].each do |bit|
    context "RS#{bit} openssl sign -> ruby verify" do
      it 'should verify'
      it 'should not verify'
    end
  end

  [256, 384, 512].each do |bit|
    context "RS#{bit} ruby sign -> openssl verify" do
      it 'should verify'
      it 'should not verify'
    end
  end

  context 'ECDSA signing, verifying' do
    [256, 384, 512].each do |bit|
      it "#{bit} should verify"
      it "#{bit} should not verify"
      it "#{bit} missing sign key"
      it "#{bit} missing verify key"
      it "#{bit} weird input"
    end
  end

  [256, 384, 512].each do |bit|
    context "ES#{bit} openssl sign -> ruby verify" do
      it 'should verify'
      it 'should not verify'
    end
  end

  [256, 384, 512].each do |bit|
    context "ES#{bit} ruby sign -> openssl verify" do
      it 'should verify'
      it 'should not verify'
    end
  end

  context 'NONE' do
    it 'should verify'
    it 'should not verify'
  end

  context 'unsupported algorithm' do
    it 'should throw'
  end
end
