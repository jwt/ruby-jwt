require 'spec_helper'
require 'jwt'

describe JWT do
  let(:jwt_header) { { 'alg' => 'HS256', 'typ' => 'JWT' } }
  let(:jwt_header_base64) { 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' }
  let(:jwt_payload) { { 'sub' => 1234567890, 'name' => 'John Doe', 'admin' => true } }
  let(:jwt_payload_base64) { 'eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ==' }
  let(:secret) { 'secret' }
  let(:jwt_signature_base64) { 'zzPVwrCDlyRQSEMsDCLrq4cjMl5t88H5T2msS_HgdqI=' }
  let(:token) { "#{jwt_header_base64}.#{jwt_payload_base64}.#{jwt_signature_base64}" }

  context 'encode' do
    it 'should match given pre-caclculated result' do
      jwt = JWT.encode(jwt_payload, secret)
      expect(jwt).to eq("#{jwt_header_base64}.#{jwt_payload_base64}.#{jwt_signature_base64}")
    end
  end

  context 'decode' do
    it 'should match given input data' do
      header, payload, signature, valid = JWT.decode(token, secret)

      expect(header).to eq(jwt_header)
      expect(payload).to eq(jwt_payload)
      expect(signature).to eq(Base64.urlsafe_decode64(jwt_signature_base64))
      expect(valid).to eq(true)
    end
  end
end
