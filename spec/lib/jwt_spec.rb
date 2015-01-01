require 'spec_helper'
require 'jwt'

describe JWT do
  let(:jwt_header) { { 'alg' => 'HS256', 'typ' => 'JWT' } }
  let(:jwt_header_base64) { 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' }
  let(:jwt_payload) { { 'sub' => 1234567890, 'name' => 'John Doe', 'admin' => true } }
  let(:jwt_payload_base64) { 'eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ' }
  let(:secret) { 'secret' }
  let(:wrong_secret) { 'wrong secret' }
  let(:jwt_signature_base64) { 'eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts' }
  let(:token) { "#{jwt_header_base64}.#{jwt_payload_base64}.#{jwt_signature_base64}" }

  context 'encode' do
    it 'should match given pre-caclculated result' do
      jwt = JWT.encode(jwt_payload, secret)
      expect(jwt).to eq("#{jwt_header_base64}.#{jwt_payload_base64}.#{jwt_signature_base64}")
    end

    it 'should create plain tokens' do
      header        = jwt_header
      header['alg'] = 'none'
      header        = JWT::Base64.encode(header.to_json)
      token         = "#{header}.#{jwt_payload_base64}."

      jwt = JWT.encode(jwt_payload, '', 'none')

      expect(jwt).to eq(token)
    end
  end

  context 'decode' do
    it 'should match given input data' do
      expect { JWT.decode(token, secret) }.not_to raise_error

      header, payload, signature, valid = JWT.decode(token, secret)

      expect(header).to eq(jwt_header)
      expect(payload).to eq(jwt_payload)
      expect(signature).to eq(JWT::Base64.decode(jwt_signature_base64))
      expect(valid).to eq(true)
    end

    it 'should handle plain tokens' do
      h        = jwt_header
      h['alg'] = 'none'
      hb64     = JWT::Base64.encode(h.to_json)
      token    = "#{hb64}.#{jwt_payload_base64}."

      header, payload, signature, valid = JWT.decode(token)

      expect(header).to eq(h)
      expect(payload).to eq(jwt_payload)
      expect(signature).to eq('')
      expect(valid).to eq(true)
    end

    context 'raises DecodeError' do
      it 'if verification fails' do
        expect { JWT.decode(token, wrong_secret) }.to raise_error(JWT::DecodeError)
      end

      it 'if input data is not valid' do
        expect { JWT.decode([token, token].join, secret) }.to raise_error(JWT::DecodeError)
      end
    end
  end

  it 'should preserve custom header fields' do
    h         = jwt_header
    h['alg']  = 'none'
    h['test'] = 'test'
    hb64      = JWT::Base64.encode(h.to_json)
    token     = "#{hb64}.#{jwt_payload_base64}."

    header, payload, signature, valid = JWT.decode(token)

    expect(header).to eq(h)
    expect(payload).to eq(jwt_payload)
    expect(signature).to eq('')
    expect(valid).to eq(true)
  end
end
