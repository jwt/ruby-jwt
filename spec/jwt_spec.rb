require 'helper'

describe JWT do
  before do
    @payload = {'foo' => 'bar', 'exp' => Time.now.to_i + 1, 'nbf' => Time.now.to_i - 1 }
  end

  it 'encodes and decodes JWTs' do
    secret = 'secret'
    jwt = JWT.encode(@payload, secret)
    decoded_payload = JWT.decode(jwt, secret)
    expect(decoded_payload).to include(@payload)
  end

  it 'encodes and decodes JWTs for RSA signatures' do
    private_key = OpenSSL::PKey::RSA.generate(512)
    jwt = JWT.encode(@payload, private_key, 'RS256')
    decoded_payload = JWT.decode(jwt, private_key.public_key)
    expect(decoded_payload).to include(@payload)
  end

  it 'encodes and decodes JWTs for ECDSA P-256 signatures' do
    private_key = OpenSSL::PKey::EC.new('prime256v1')
    private_key.generate_key
    public_key = OpenSSL::PKey::EC.new(private_key)
    public_key.private_key = nil
    jwt = JWT.encode(@payload, private_key, 'ES256')
    decoded_payload = JWT.decode(jwt, public_key)
    expect(decoded_payload).to include(@payload)
  end

  it 'encodes and decodes JWTs for ECDSA P-384 signatures' do
    private_key = OpenSSL::PKey::EC.new('secp384r1')
    private_key.generate_key
    public_key = OpenSSL::PKey::EC.new(private_key)
    public_key.private_key = nil
    jwt = JWT.encode(@payload, private_key, 'ES384')
    decoded_payload = JWT.decode(jwt, public_key)
    expect(decoded_payload).to include(@payload)
  end

  it 'encodes and decodes JWTs for ECDSA P-521 signatures' do
    private_key = OpenSSL::PKey::EC.new('secp521r1')
    private_key.generate_key
    public_key = OpenSSL::PKey::EC.new(private_key)
    public_key.private_key = nil
    jwt = JWT.encode(@payload, private_key, 'ES512')
    decoded_payload = JWT.decode(jwt, public_key)
    expect(decoded_payload).to include(@payload)
  end

  it 'encodes and decodes JWTs with custom header fields' do
    private_key = OpenSSL::PKey::RSA.generate(512)
    jwt = JWT.encode(@payload, private_key, 'RS256', {'kid' => 'default'})
    decoded_payload = JWT.decode(jwt) do |header|
      expect(header['kid']).to eq('default')
      private_key.public_key
    end
    expect(decoded_payload).to include(@payload)
  end

  it 'raises encode exception when ECDSA algorithm does not match key' do
    private_key = OpenSSL::PKey::EC.new('prime256v1')
    private_key.generate_key
    expect do
      JWT.encode(@payload, private_key, 'ES512')
    end.to raise_error(JWT::IncorrectAlgorithm, 'payload algorithm is ES512 but ES256 signing key was provided')
  end

  it 'decodes valid JWTs' do
    example_payload = {'hello' => 'world'}
    example_secret = 'secret'
    example_jwt = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8'
    decoded_payload = JWT.decode(example_jwt, example_secret)
    expect(decoded_payload).to include(example_payload)
  end

  it 'decodes valid JWTs with iss' do
    example_payload = {'hello' => 'world', 'iss' => 'jwtiss'}
    example_secret = 'secret'
    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaXNzIjoiand0aXNzIn0.nTZkyYfpGUyKULaj45lXw_1gXXjHvGW4h5V7okHdUqQ'
    decoded_payload = JWT.decode(example_jwt, example_secret, true, {'iss' => 'jwtiss'})
    expect(decoded_payload).to include(example_payload)
  end

  it 'raises invalid issuer' do
    # example_payload = {'hello' => 'world', 'iss' => 'jwtiss'}
    example_payload2 = {'hello' => 'world'}

    example_secret = 'secret'

    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaXNzIjoiand0aXNzIn0.nTZkyYfpGUyKULaj45lXw_1gXXjHvGW4h5V7okHdUqQ'
    expect{ JWT.decode(example_jwt, example_secret, true, {:verify_iss => true, 'iss' => 'jwt_iss'}) }.to raise_error(JWT::InvalidIssuerError)

    example_jwt2 = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8'
    decode_payload2 = JWT.decode(example_jwt2, example_secret, true, {'iss' => 'jwt_iss'})
    expect(decode_payload2).to include(example_payload2)
  end

  it 'decodes valid JWTs with iat' do
    example_payload = {'hello' => 'world', 'iat' => 1425917209}
    example_secret = 'secret'
    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0IjoxNDI1OTE3MjA5fQ.m4F-Ugo7aLnLunBBO3BeDidyWMx8T9eoJz6FW2rgQhU'
    decoded_payload = JWT.decode(example_jwt, example_secret, true, {'iat' => true})
    expect(decoded_payload).to include(example_payload)
  end

  it 'raises decode exception when iat is invalid' do
    # example_payload = {'hello' => 'world', 'iat' => 'abc'}
    example_secret = 'secret'
    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0IjoiMTQyNTkxNzIwOSJ9.Mn_vk61xWjIhbXFqAB0nFmNkDiCmfzUgl_LaCKRT6S8'
    expect{ JWT.decode(example_jwt, example_secret, true, {:verify_iat => true, 'iat' => 1425917209}) }.to raise_error(JWT::InvalidIatError)
  end

  it 'decodes valid JWTs with jti' do
    example_payload = {'hello' => 'world', 'iat' => 1425917209, 'jti' => Digest::MD5.hexdigest('secret:1425917209')}
    example_secret = 'secret'
    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0IjoxNDI1OTE3MjA5LCJqdGkiOiI1NWM3NzZlMjFmN2NiZDg3OWMwNmZhYzAxOGRhYzQwMiJ9.ET0hb-VTUOL3M22oG13ofzvGPLMAncbF8rdNDIqo8tg'
    decoded_payload = JWT.decode(example_jwt, example_secret, true, {'jti' => Digest::MD5.hexdigest('secret:1425917209')})
    expect(decoded_payload).to include(example_payload)
  end

  it 'raises decode exception when jti is invalid' do
    # example_payload = {'hello' => 'world', 'iat' => 1425917209, 'jti' => Digest::MD5.hexdigest('secret:1425917209')}
    example_secret = 'secret'
    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0IjoxNDI1OTE3MjA5LCJqdGkiOiI1NWM3NzZlMjFmN2NiZDg3OWMwNmZhYzAxOGRhYzQwMiJ9.ET0hb-VTUOL3M22oG13ofzvGPLMAncbF8rdNDIqo8tg'
    expect{ JWT.decode(example_jwt, example_secret, true, {:verify_jti => true, 'jti' => Digest::MD5.hexdigest('secret:1425922032')}) }.to raise_error(JWT::InvalidJtiError)
    # expect{ JWT.decode(example_jwt, example_secret) }.to raise_error(JWT::InvalidJtiError)
  end

  it 'raises decode exception when jti without iat' do
    # example_payload = {'hello' => 'world', 'jti' => Digest::MD5.hexdigest('secret:1425917209')}
    example_secret = 'secret'
    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwianRpIjoiNTVjNzc2ZTIxZjdjYmQ4NzljMDZmYWMwMThkYWM0MDIifQ.n0foJCnCM_-_xUvG_TOmR9mYpL2y0UqZOD_gv33djeE'
    expect{ JWT.decode(example_jwt, example_secret, true, {:verify_jti => true, 'jti' => Digest::MD5.hexdigest('secret:1425922032')}) }.to raise_error(JWT::InvalidJtiError)
  end

  it 'decodes valid JWTs with aud' do
    example_payload = {'hello' => 'world', 'aud' => 'url:pnd'}
    example_payload2 = {'hello' => 'world', 'aud' => ['url:pnd', 'aud:yes']}
    example_secret = 'secret'
    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiYXVkIjoidXJsOnBuZCJ9._gT5veUtNiZD7wLEC6Gd0-nkQV3cl1z8G0zXq8qcd-8'
    example_jwt2 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiYXVkIjpbInVybDpwbmQiLCJhdWQ6eWVzIl19.qNPNcT4X9B5uI91rIwbW2bIPTsp8wbRYW3jkZkrmqbQ'
    decoded_payload = JWT.decode(example_jwt, example_secret, true, {'aud' => 'url:pnd'})
    decoded_payload2 = JWT.decode(example_jwt2, example_secret, true, {'aud' => 'url:pnd'})
    expect(decoded_payload).to include(example_payload)
    expect(decoded_payload2).to include(example_payload2)
  end

  it 'raises deode exception when aud is invalid' do
    # example_payload = {'hello' => 'world', 'aud' => 'url:pnd'}
    example_secret = 'secret'
    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiYXVkIjoidXJsOnBuZCJ9._gT5veUtNiZD7wLEC6Gd0-nkQV3cl1z8G0zXq8qcd-8'
    expect{ JWT.decode(example_jwt, example_secret, true, {:verify_aud => true, 'aud' => 'wrong:aud'}) }.to raise_error(JWT::InvalidAudError)
  end

  it 'decodes valid JWTs with sub' do
    example_payload = {'hello' => 'world', 'sub' => 'subject'}
    example_secret = 'secret'
    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwic3ViIjoic3ViamVjdCJ9.QUnNVZm4SPB4vP2zY9m1LoUSOx-5oGXBhj7R89D_UtA'
    decoded_payload = JWT.decode(example_jwt, example_secret, true, {'sub' => 'subject'})
    expect(decoded_payload).to include(example_payload)
  end

  it 'raise decode exception when the sub is invalid' do
    # example_payload = {'hello' => 'world', 'sub' => 'subject'}
    # TODO: Test not working
    example_secret = 'secret'
    example_jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwic3ViIjoic3ViamVjdCJ9.QUnNVZm4SPB4vP2zY9m1LoUSOx-5oGXBhj7R89D_UtA'
    # expect{ JWT.decode(example_jwt, example_secret, true, {:verify_iss => true, 'iss' => 'subject'}) }.to raise_error(JWT::InvalidSubError)
  end

  it 'raises decode exception when the token is invalid' do
    example_secret = 'secret'
    # Same as above exmaple with some random bytes replaced
    example_jwt = 'eyJhbGciOiAiSFMyNTYiLCAidHiMomlwIjogIkJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8'
    expect { JWT.decode(example_jwt, example_secret) }.to raise_error(JWT::DecodeError)
  end

  it 'raises verification exception with wrong hmac key' do
    right_secret = 'foo'
    bad_secret = 'bar'
    jwt_message = JWT.encode(@payload, right_secret, 'HS256')
    expect { JWT.decode(jwt_message, bad_secret) }.to raise_error(JWT::VerificationError)
  end

  it 'raises decode exception when ECDSA algorithm does not match key' do
    right_private_key = OpenSSL::PKey::EC.new('prime256v1')
    right_private_key.generate_key
    right_public_key = OpenSSL::PKey::EC.new(right_private_key)
    right_public_key.private_key = nil
    bad_private_key = OpenSSL::PKey::EC.new('secp384r1')
    bad_private_key.generate_key
    bad_public_key = OpenSSL::PKey::EC.new(bad_private_key)
    bad_public_key.private_key = nil
    jwt = JWT.encode(@payload, right_private_key, 'ES256')
    expect do
      JWT.decode(jwt, bad_public_key)
    end.to raise_error(JWT::IncorrectAlgorithm, 'payload algorithm is ES256 but ES384 verification key was provided')
  end

  it 'raises verification exception with wrong rsa key' do
    right_private_key = OpenSSL::PKey::RSA.generate(512)
    bad_private_key = OpenSSL::PKey::RSA.generate(512)
    jwt = JWT.encode(@payload, right_private_key, 'RS256')
    expect { JWT.decode(jwt, bad_private_key.public_key) }.to raise_error(JWT::VerificationError)
  end

  it 'raises verification exception with wrong ECDSA key' do
    right_private_key = OpenSSL::PKey::EC.new('prime256v1')
    right_private_key.generate_key
    bad_private_key = OpenSSL::PKey::EC.new('prime256v1')
    bad_private_key.generate_key
    bad_public_key = OpenSSL::PKey::EC.new(bad_private_key)
    bad_public_key.private_key = nil
    jwt = JWT.encode(@payload, right_private_key, 'ES256')
    expect { JWT.decode(jwt, bad_public_key) }.to raise_error(JWT::VerificationError)
  end

  it 'raises decode exception with invalid signature' do
    example_secret = 'secret'
    example_jwt = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.'
    expect { JWT.decode(example_jwt, example_secret) }.to raise_error(JWT::DecodeError)
  end

  it 'raises decode exception with nonexistent header' do
    expect { JWT.decode('..stuff') }.to raise_error(JWT::DecodeError)
  end

  it 'raises decode exception with nonexistent payload' do
    expect { JWT.decode('eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9..stuff') }.to raise_error(JWT::DecodeError)
  end

  it 'raises decode exception with nil jwt' do
    expect { JWT.decode(nil) }.to raise_error(JWT::DecodeError)
  end

  it 'allows decoding without key' do
    right_secret = 'foo'
    bad_secret = 'bar'
    jwt = JWT.encode(@payload, right_secret)
    decoded_payload = JWT.decode(jwt, bad_secret, false)
    expect(decoded_payload).to include(@payload)
  end

  it 'checks the key when verify is truthy' do
    right_secret = 'foo'
    bad_secret = 'bar'
    jwt = JWT.encode(@payload, right_secret)
    verify = 'yes' =~ /^y/i
    expect { JWT.decode(jwt, bad_secret, verify) }.to raise_error(JWT::DecodeError)
  end

  it 'raises exception on unsupported crypto algorithm' do
    expect { JWT.encode(@payload, 'secret', 'HS1024') }.to raise_error(NotImplementedError)
  end

  it 'raises exception when decoded with a different algorithm than it was encoded with' do
    jwt = JWT.encode(@payload, 'foo', 'HS384')
    expect { JWT.decode(jwt, 'foo', true, :algorithm => 'HS512') }.to raise_error(JWT::IncorrectAlgorithm)
  end

  it 'does not raise exception when encoded with the expected algorithm' do
    jwt = JWT.encode(@payload, 'foo', 'HS512')
    JWT.decode(jwt, 'foo', true, :algorithm => 'HS512')
  end

  it 'encodes and decodes plaintext JWTs' do
    jwt = JWT.encode(@payload, nil, nil)
    expect(jwt.split('.').length).to eq(2)
    decoded_payload = JWT.decode(jwt, nil, nil)
    expect(decoded_payload).to include(@payload)
  end

  it 'requires a signature segment when verify is truthy' do
    jwt = JWT.encode(@payload, nil, nil)
    expect(jwt.split('.').length).to eq(2)
    expect { JWT.decode(jwt, nil, true) }.to raise_error(JWT::DecodeError)
  end

  it 'does not use == to compare digests' do
    secret = 'secret'
    jwt = JWT.encode(@payload, secret)
    crypto_segment = jwt.split('.').last

    signature = JWT.base64url_decode(crypto_segment)
    expect(signature).not_to receive('==')
    expect(JWT).to receive(:base64url_decode).with(crypto_segment).once.and_return(signature)
    expect(JWT).to receive(:base64url_decode).at_least(:once).and_call_original

    JWT.decode(jwt, secret)
  end

  it 'raises error when expired' do
    expired_payload = @payload.clone
    expired_payload['exp'] = Time.now.to_i - 1
    secret = 'secret'
    jwt = JWT.encode(expired_payload, secret)
    expect { JWT.decode(jwt, secret) }.to raise_error(JWT::ExpiredSignature)
  end

  it 'raise ExpiredSignature even when exp claims is a string' do
    expired_payload = @payload.clone
    expired_payload['exp'] = (Time.now.to_i).to_s
    secret = 'secret'
    jwt = JWT.encode(expired_payload, secret)
    expect { JWT.decode(jwt, secret) }.to raise_error(JWT::ExpiredSignature)
  end

  it 'performs normal decode with skipped expiration check' do
    expired_payload = @payload.clone
    expired_payload['exp'] = Time.now.to_i - 1
    secret = 'secret'
    jwt = JWT.encode(expired_payload, secret)
    decoded_payload = JWT.decode(jwt, secret, true, {:verify_expiration => false})
    expect(decoded_payload).to include(expired_payload)
  end

  it 'performs normal decode using leeway' do
    expired_payload = @payload.clone
    expired_payload['exp'] = Time.now.to_i - 2
    secret = 'secret'
    jwt = JWT.encode(expired_payload, secret)
    decoded_payload = JWT.decode(jwt, secret, true, {:leeway => 3})
    expect(decoded_payload).to include(expired_payload)
  end

  it 'raises error when before nbf' do
    immature_payload = @payload.clone
    immature_payload['nbf'] = Time.now.to_i + 1
    secret = 'secret'
    jwt = JWT.encode(immature_payload, secret)
    expect { JWT.decode(jwt, secret) }.to raise_error(JWT::ImmatureSignature)
  end

  it 'doesnt raise error when after nbf' do
    mature_payload = @payload.clone
    secret = 'secret'
    jwt = JWT.encode(mature_payload, secret)
    decoded_payload = JWT.decode(jwt, secret, true, {:verify_expiration => false})
    expect(decoded_payload).to include(mature_payload)
  end

  it 'raise ImmatureSignature even when nbf claim is a string' do
    immature_payload = @payload.clone
    immature_payload['nbf'] = (Time.now.to_i).to_s
    secret = 'secret'
    jwt = JWT.encode(immature_payload, secret)
    expect { JWT.decode(jwt, secret) }.to raise_error(JWT::ImmatureSignature)
  end

  it 'performs normal decode with skipped not before check' do
    immature_payload = @payload.clone
    immature_payload['nbf'] = Time.now.to_i + 2
    secret = 'secret'
    jwt = JWT.encode(immature_payload, secret)
    decoded_payload = JWT.decode(jwt, secret, true, {:verify_not_before => false})
    expect(decoded_payload).to include(immature_payload)
  end

  it 'performs normal decode using leeway' do
    immature_payload = @payload.clone
    immature_payload['nbf'] = Time.now.to_i - 2
    secret = 'secret'
    jwt = JWT.encode(immature_payload, secret)
    decoded_payload = JWT.decode(jwt, secret, true, {:leeway => 3})
    expect(decoded_payload).to include(immature_payload)
  end

  describe 'secure comparison' do
    it 'returns true if strings are equal' do
      expect(JWT.secure_compare('Foo', 'Foo')).to be true
    end

    it 'returns false if either input is nil or empty' do
      [nil, ''].each do |bad|
        expect(JWT.secure_compare(bad, 'Foo')).to be false
        expect(JWT.secure_compare('Foo', bad)).to be false
      end
    end

    it 'retuns false if the strings are different' do
      expect(JWT.secure_compare('Foo', 'Bar')).to be false
    end
  end

  # no method should leave OpenSSL.errors populated
  after do
    expect(OpenSSL.errors).to be_empty
  end

  it 'raise exception on invalid signature' do
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

  describe 'urlsafe base64 encoding' do
    it 'replaces + and / with - and _' do
      allow(Base64).to receive(:encode64) { 'string+with/non+url-safe/characters_' }
      expect(JWT.base64url_encode('foo')).to eq('string-with_non-url-safe_characters_')
    end
  end

  describe 'decoded_segments' do
    it 'allows access to the decoded header and payload' do
      secret = 'secret'
      jwt = JWT.encode(@payload, secret)
      decoded_segments = JWT.decoded_segments(jwt)
      expect(decoded_segments.size).to eq(4)
      expect(decoded_segments[0]).to eq({'typ' => 'JWT', 'alg' => 'HS256'})
      expect(decoded_segments[1]).to eq(@payload)
    end
  end
end
