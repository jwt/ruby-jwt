require 'spec_helper'
require_relative '../../lib/jws'

describe JWS do
  [256, 384, 512].each do |bit|
    context "HMAC using SHA-#{bit} hash algorithm" do
      it 'should verify'
      it 'should not verify'
      it 'should match payload'
      it 'should match header'
    end
  end

  [256, 384, 512].each do |bit|
    context "RSASSA using SHA-#{bit} hash algorithm" do
      it 'should verify'
      it 'should not verify'
      it 'should match payload'
      it 'should match header'
    end
  end

  [256, 384, 512].each do |bit|
    context "ECDSA using P-#{bit} curve and SHA-#{bit} hash algorithm" do
      it 'should verify'
      it 'should not verify'
      it 'should match payload'
      it 'should match header'
    end
  end
  
  context 'NONE' do
    it 'should verify'
    it 'should still verify'
    it 'should match payload'
    it 'should match header'
  end

  context 'unsupported algorithm' do
    it 'should throw'
  end
end
