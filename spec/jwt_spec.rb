require 'helper'

describe JWT do
  before do
    @payload = {"foo" => "bar"}
  end

  it "encodes and decodes JWTs" do
    secret = "secret"
    jwt = JWT.encode(@payload, secret)
    decoded_payload = JWT.decode(jwt, secret)
    decoded_payload.should == @payload
  end

  it "encodes and decodes JWTs for RSA signatures" do
    private_key = OpenSSL::PKey::RSA.generate(512)
    jwt = JWT.encode(@payload, private_key, "RS256")
    decoded_payload = JWT.decode(jwt, private_key.public_key)
    decoded_payload.should == @payload
  end

  it "encodes and decodes JWTs with custom header fields" do
    private_key = OpenSSL::PKey::RSA.generate(512)
    jwt = JWT.encode(@payload, private_key, "RS256", {"kid" => 'default'})
    decoded_payload = JWT.decode(jwt) do |header|
      header["kid"].should == 'default'
      private_key.public_key
    end
    decoded_payload.should == @payload
  end

  it "decodes valid JWTs" do
    example_payload = {"hello" => "world"}
    example_secret = 'secret'
    example_jwt = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8'
    decoded_payload = JWT.decode(example_jwt, example_secret)
    decoded_payload.should == example_payload
  end

  it "raises exception with wrong hmac key" do
    right_secret = 'foo'
    bad_secret = 'bar'
    jwt_message = JWT.encode(@payload, right_secret, "HS256")
    lambda { JWT.decode(jwt_message, bad_secret) }.should raise_error(JWT::DecodeError)
  end

  it "raises exception with wrong rsa key" do
    right_private_key = OpenSSL::PKey::RSA.generate(512)
    bad_private_key = OpenSSL::PKey::RSA.generate(512)
    jwt = JWT.encode(@payload, right_private_key, "RS256")
    lambda { JWT.decode(jwt, bad_private_key.public_key) }.should raise_error(JWT::DecodeError)
  end

  it "allows decoding without key" do
    right_secret = 'foo'
    bad_secret = 'bar'
    jwt = JWT.encode(@payload, right_secret)
    decoded_payload = JWT.decode(jwt, bad_secret, false)
    decoded_payload.should == @payload
  end

  it "raises exception on unsupported crypto algorithm" do
    lambda { JWT.encode(@payload, "secret", 'HS1024') }.should raise_error(NotImplementedError)
  end

  it "encodes and decodes plaintext JWTs" do
    jwt = JWT.encode(@payload, nil, nil)
    jwt.split('.').length.should == 2
    decoded_payload = JWT.decode(jwt, nil, nil)
    decoded_payload.should == @payload
  end

  it "raise exception on invalid signature" do
    pubkey = OpenSSL::PKey::RSA.new(<<-PUBKEY)
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxCaY7425h964bjaoLeUm
SlZ8sK7VtVk9zHbGmZh2ygGYwfuUf2bmMye2Ofv99yDE/rd4loVIAcu7RVvDRgHq
3/CZTnIrSvHsiJQsHBNa3d+F1ihPfzURzf1M5k7CFReBj2SBXhDXd57oRfBQj12w
CVhhwP6kGTAWuoppbIIIBfNF2lE/Nvm7lVVYQqL9xOrP/AQ4xRbpQlB8Ll9sO9Or
SvbWhCDa/LMOWxHdmrcJi6XoSg1vnOyCoKbyAoauTt/XqdkHbkDdQ6HFbJieu9il
LDZZNliPhfENuKeC2MCGVXTEu8Cqhy1w6e4axavLlXoYf4laJIZ/e7au8SqDbY0B
xwIDAQAB
-----END PUBLIC KEY-----
PUBKEY
    jwt = (
      'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiY' +
      'XVkIjoiMTA2MDM1Nzg5MTY4OC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSI' +
      'sImNpZCI6IjEwNjAzNTc4OTE2ODguYXBwcy5nb29nbGV1c2VyY29udGVudC5jb' +
      '20iLCJpZCI6IjExNjQ1MjgyNDMwOTg1Njc4MjE2MyIsInRva2VuX2hhc2giOiJ' +
      '0Z2hEOUo4bjhWME4ydmN3NmVNaWpnIiwiaWF0IjoxMzIwNjcwOTc4LCJleHAiO' +
      'jEzMjA2NzQ4Nzh9.D8x_wirkxDElqKdJBcsIws3Ogesk38okz6MN7zqC7nEAA7' +
      'wcy1PxsROY1fmBvXSer0IQesAqOW-rPOCNReSn-eY8d53ph1x2HAF-AzEi3GOl' +
      '6hFycH8wj7Su6JqqyEbIVLxE7q7DkAZGaMPkxbTHs1EhSd5_oaKQ6O4xO3ZnnT4'
    )
    lambda { JWT.decode(jwt, pubkey, true) }.should raise_error(JWT::DecodeError)
  end
end
