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
end
