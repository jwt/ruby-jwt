require 'helper'

describe JWT do
  before do
    @payload = {"foo" => "bar"}
  end

  it "encodes and decodes JWTs" do
    secret = "secret"
    jwt = JWT.encode(@payload, secret)
    decoded_payload = JWT.decode(jwt, secret)
    expect(decoded_payload).to include(@payload)
  end

  it "encodes and decodes JWTs for RSA signatures" do
    private_key = OpenSSL::PKey::RSA.generate(512)
    jwt = JWT.encode(@payload, private_key, "RS256")
    decoded_payload = JWT.decode(jwt, private_key.public_key)
    expect(decoded_payload).to include(@payload)
  end

  it "encodes and decodes JWTs with custom header fields" do
    private_key = OpenSSL::PKey::RSA.generate(512)
    jwt = JWT.encode(@payload, private_key, "RS256", {"kid" => 'default'})
    decoded_payload = JWT.decode(jwt) do |header|
      expect(header["kid"]).to eq('default')
      private_key.public_key
    end
    expect(decoded_payload).to include(@payload)
  end

  it "decodes valid JWTs" do
    example_payload = {"hello" => "world"}
    example_secret = 'secret'
    example_jwt = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8'
    decoded_payload = JWT.decode(example_jwt, example_secret)
    expect(decoded_payload).to include(example_payload)
  end

  it "raises exception when the token is invalid" do
    example_secret = 'secret'
    # Same as above exmaple with some random bytes replaced
    example_jwt = 'eyJhbGciOiAiSFMyNTYiLCAidHiMomlwIjogIkJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8'
    expect { JWT.decode(example_jwt, example_secret) }.to raise_error(JWT::DecodeError)
  end

  it "raises exception with wrong hmac key" do
    right_secret = 'foo'
    bad_secret = 'bar'
    jwt_message = JWT.encode(@payload, right_secret, "HS256")
    expect { JWT.decode(jwt_message, bad_secret) }.to raise_error(JWT::DecodeError)
  end

  it "raises exception with wrong rsa key" do
    right_private_key = OpenSSL::PKey::RSA.generate(512)
    bad_private_key = OpenSSL::PKey::RSA.generate(512)
    jwt = JWT.encode(@payload, right_private_key, "RS256")
    expect { JWT.decode(jwt, bad_private_key.public_key) }.to raise_error(JWT::DecodeError)
  end

  it "raises exception with invalid signature" do
    example_secret = 'secret'
    example_jwt = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.'
    expect { JWT.decode(example_jwt, example_secret) }.to raise_error(JWT::DecodeError)
  end

  it "raises exception with nonexistent header" do
    expect { JWT.decode("..stuff") }.to raise_error(JWT::DecodeError)
  end

  it "raises exception with nonexistent payload" do
    expect { JWT.decode("eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9..stuff") }.to raise_error(JWT::DecodeError)
  end

  it "raises exception with nil jwt" do
    expect { JWT.decode(nil) }.to raise_error(JWT::DecodeError)
  end

  it "allows decoding without key" do
    right_secret = 'foo'
    bad_secret = 'bar'
    jwt = JWT.encode(@payload, right_secret)
    decoded_payload = JWT.decode(jwt, bad_secret, false)
    expect(decoded_payload).to include(@payload)
  end

  it "checks the key when verify is truthy" do
    right_secret = 'foo'
    bad_secret = 'bar'
    jwt = JWT.encode(@payload, right_secret)
    verify = "yes" =~ /^y/i
    expect { JWT.decode(jwt, bad_secret, verify) }.to raise_error(JWT::DecodeError)
  end

  it "raises exception on unsupported crypto algorithm" do
    expect { JWT.encode(@payload, "secret", 'HS1024') }.to raise_error(NotImplementedError)
  end

  it "encodes and decodes plaintext JWTs" do
    jwt = JWT.encode(@payload, nil, nil)
    expect(jwt.split('.').length).to eq(2)
    decoded_payload = JWT.decode(jwt, nil, nil)
    expect(decoded_payload).to include(@payload)
  end

  it "requires a signature segment when verify is truthy" do
    jwt = JWT.encode(@payload, nil, nil)
    expect(jwt.split('.').length).to eq(2)
    expect { JWT.decode(jwt, nil, true) }.to raise_error(JWT::DecodeError)
  end

  it "does not use == to compare digests" do
    secret = "secret"
    jwt = JWT.encode(@payload, secret)
    crypto_segment = jwt.split(".").last

    signature = JWT.base64url_decode(crypto_segment)
    expect(signature).not_to receive('==')
    expect(JWT).to receive(:base64url_decode).with(crypto_segment).once.and_return(signature)
    expect(JWT).to receive(:base64url_decode).at_least(:once).and_call_original

    JWT.decode(jwt, secret)
  end

  describe "secure comparison" do
    it "returns true if strings are equal" do
      expect(JWT.secure_compare("Foo", "Foo")).to be_true
    end

    it "returns false if either input is nil or empty" do
      [nil, ""].each do |bad|
        expect(JWT.secure_compare(bad, "Foo")).to be_false
        expect(JWT.secure_compare("Foo", bad)).to be_false
      end
    end

    it "retuns false if the strings are different" do
      expect(JWT.secure_compare("Foo", "Bar")).to be_false
    end
  end

  # no method should leave OpenSSL.errors populated
  after do
    expect(OpenSSL.errors).to be_empty
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
    expect { JWT.decode(jwt, pubkey, true) }.to raise_error(JWT::DecodeError)
  end

  describe "urlsafe base64 encoding" do
    it "replaces + and / with - and _" do
      allow(Base64).to receive(:encode64) { "string+with/non+url-safe/characters_" }
      expect(JWT.base64url_encode("foo")).to eq("string-with_non-url-safe_characters_")
    end
  end

  describe 'decoded_segments' do
    it "allows access to the decoded header and payload" do
      secret = "secret"
      jwt = JWT.encode(@payload, secret)
      decoded_segments = JWT.decoded_segments(jwt)
      expect(decoded_segments.size).to eq(4)
      expect(decoded_segments[0]).to eq({"typ" => "JWT", "alg" => "HS256"})
      expect(decoded_segments[1]).to eq(@payload)
    end
  end
end
