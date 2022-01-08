# frozen_string_literal: true

require 'securerandom'
require 'zlib'

RSpec.describe 'Deflating payload processor' do
  let(:secret) { SecureRandom.hex }
  let(:payload) { { 'pay' => 'load'} }

  subject(:extension) do
    the_secret = secret
    Class.new do
      include JWT

      algorithm 'HS512'
      algorithms 'HS5256'
      signing_key the_secret

      encode_payload do |payload|
        io = StringIO.new
        Zlib::GzipWriter.new(io).tap do |gz|
          gz.write(::JWT::JSON.generate(payload))
          gz.close
        end
        ::Base64.urlsafe_encode64(io.string, padding: true)
      end

      decode_payload do |raw_payload|
        raw_json = Zlib::GzipReader.new(StringIO.new(::Base64.urlsafe_decode64(raw_payload))).read
        ::JWT::JSON.parse(raw_json)
      end
    end
  end

  context 'when encoding' do
    it 'the encoded payload looks like its zipped' do
      expect(subject.encode!(payload).split('.')[1]).to match(/H4.*==/)
    end
  end

  context 'when decoding presigned and zipped token' do
    let(:secret) { 's3cr3t' }
    let(:presigned_token) { 'eyJhbGciOiJIUzUxMiJ9.H4sIAKTUyWEAA6tWKkisVLJSyslPTFGqBQAsM7zZDgAAAA==.GK1DXdMN7i6OA_1_xUYU3lThZwY94MgUYRivRIaLTIP-yrmZfxLrbpe3Llkrr1HIrDQhjPPwskiR5oob14hv9A' }

    it 'verifies and decodes the payload' do
      expect(subject.decode!(presigned_token)).to eq([{'pay' => 'load'}, {'alg' => 'HS512'}])
    end
  end
end
