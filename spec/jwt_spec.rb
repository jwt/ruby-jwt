require 'spec_helper'
require 'jwt'

describe JWT do
  let(:payload) { { 'user_id' => 'some@user.tld' } }

  let :data do
    {
      :secret => 'My$ecretK3y',
      :rsa_private => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'rsa-2048-private.pem'))),
      :rsa_public => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'rsa-2048-public.pem'))),
      :wrong_rsa_private => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'rsa-2048-wrong-public.pem'))),
      :wrong_rsa_public => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'rsa-2048-wrong-public.pem'))),
      'ES256_private' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec256-private.pem'))),
      'ES256_public' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec256-public.pem'))),
      'ES384_private' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec384-private.pem'))),
      'ES384_public' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec384-public.pem'))),
      'ES512_private' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec512-private.pem'))),
      'ES512_public' => OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec512-public.pem'))),
      'NONE' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.',
      'HS256' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.tCGvlClld0lbQ3NZaH8y53n5RSBr3zlS4Oy5bXqvzZQ',
      'HS384' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.sj1gc01SawlJSrPZgmveifJ8CzZRYAWjejWm4FRaGaAISESJ9Ncf12fCz2vHrITm',
      'HS512' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.isjhsWMZpRQOWw6LKtlY4L6tMDNkLr0qZ3bQe_xRFXWhzVvJlkclTbLVa1J6Dlj2WyZ_I1jEobTaFMDoXPzwWg',
      'RS256' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.u82QrhjZTtwve5akvfWS_4LPywbkb1Yp0nUwZJWtTW0ID7dY9rRiQF5KGj2UDLZotqRlUjyNQgE_hB5BBzICDQdCjQHQoYWE5n_D2wV4PMu7Qg3FVKoBFbf8ee6irodu10fgYxpUIZtvbWw52_6k6A9IoSLSzx_lCcxoVGdW90dUuKhBcZkDtY5WNuQg7MiDthupSL1-V4Y1jmT_7o8tLNGFiocyZfGNw4yGpEOGNvD5WePNit0xsnbj6dEquovUvSFKsMaQXp2PVDEkLOiLMcyk0RrHqrHw2eNSCquWTH8PhX5Up-CVmjQM5zF9ibkaiq8NyPtsy-7rgtbyVMqXBQ',
      'RS384' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.2_jPwOsUWJ-3r6lXMdJGPdhLNJQSSEmY2mrDXCwNJk-2YhMIqKAzJJCbyso_A1hS7BVkXmHt54RCcNJXroZBOgmGavCcYTPMaT6sCvVVvJJ_wn7jzKHNAJfL5nWeynTQIBWmL-m_v9QpZAgPALdeqjPRv4JHePZm23kvrUgQOxef2ldXv1l6IB3zfF72uEbk9T5pKBvgeeeQ46xm_HtkpXqMdqcTHawUXeXhuiWxuWfy9pAvhm8ivxwJhiQ15-sQNBlS9lG1_gQz1xaZ_Ou_n1nhNfGwpK5HeS0AgmqsqyCOvaGHeAuAOPZ_dSC3cFKu2AP7kc6_AKBgwJzh4agkXg',
      'RS512' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.abwof7BqTvuLkN69OhEuFTP7vjGzfvAvooQdwIRne_a88MsjCq31n4UPvyIlY9_8u69rpU79RbMsrq_UZ6L85zP83EcyYI-HOfFZgYDAL3DJ7biBD99JTzyOsH_2i_E6yCkevjEX6uL_Am_C7jpWyePJQkYzTFni6mW4W1T9UobiVGA1tIZ-XOJDPHHxZkGu6W8lKW0UCsr9Ge2SCSlTs_LDSOa34gqMC5GP89unhLqSMqEMJ_Nm6Rj0rnmk87wBZM-b04LLteWuEU59QDNa4nMTjfXW74U4hX9n5EECDPQdQMecgxlUbFunAfZaoNzP4m7H4vux2FzYkjkXhdqnnw',
      'ES256' => '',
      'ES384' => '',
      'ES512' => ''
    }
  end

  after(:each) do
    expect(OpenSSL.errors).to be_empty
  end

  context 'alg: NONE' do
    let(:alg) { 'none' }

    it 'should generate a valid token' do
      token = JWT.encode payload, nil, alg

      expect(token).to eq data['NONE']
    end

    it 'should decode a valid token' do
      jwt_payload, header = JWT.decode data['NONE'], nil, false

      expect(header['alg']).to eq alg
      expect(jwt_payload).to eq payload
    end
  end

  %w(HS256 HS384 HS512).each do |alg|
    context "alg: #{alg}" do
      it 'should generate a valid token' do
        token = JWT.encode payload, data[:secret], alg

        expect(token).to eq data[alg]
      end

      it 'should decode a valid token' do
        jwt_payload, header = JWT.decode data[alg], data[:secret]

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end

      it 'wrong secret should raise JWT::DecodeError' do
        expect do
          JWT.decode data[alg], 'wrong_secret'
        end.to raise_error JWT::DecodeError
      end

      it 'wrong secret and verify = false should not raise JWT::DecodeError' do
        expect do
          JWT.decode data[alg], 'wrong_secret', false
        end.not_to raise_error
      end
    end
  end

  %w(RS256 RS384 RS512).each do |alg|
    context "alg: #{alg}" do
      it 'should generate a valid token' do
        token = JWT.encode payload, data[:rsa_private], alg

        expect(token).to eq data[alg]
      end

      it 'should decode a valid token' do
        jwt_payload, header = JWT.decode data[alg], data[:rsa_public]

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end

      it 'wrong key should raise JWT::DecodeError' do
        key = OpenSSL::PKey.read File.read(File.join(CERT_PATH, 'rsa-2048-wrong-public.pem'))

        expect do
          JWT.decode data[alg], key
        end.to raise_error JWT::DecodeError
      end

      it 'wrong key and verify = false should not raise JWT::DecodeError' do
        key = OpenSSL::PKey.read File.read(File.join(CERT_PATH, 'rsa-2048-wrong-public.pem'))

        expect do
          JWT.decode data[alg], key, false
        end.not_to raise_error
      end
    end
  end

  %w(ES256 ES384 ES512).each do |alg|
    context "alg: #{alg}" do
      before(:each) do
        data[alg] = JWT.encode payload, data["#{alg}_private"], alg
      end

      let(:wrong_key) { OpenSSL::PKey.read(File.read(File.join(CERT_PATH, 'ec256-wrong-public.pem'))) }

      it 'should generate a valid token' do
        jwt_payload, header = JWT.decode data[alg], data["#{alg}_public"]

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end

      it 'should decode a valid token' do
        jwt_payload, header = JWT.decode data[alg], data["#{alg}_public"]

        expect(header['alg']).to eq alg
        expect(jwt_payload).to eq payload
      end

      it 'wrong key should raise JWT::DecodeError' do
        expect do
          JWT.decode data[alg], wrong_key
        end.to raise_error JWT::DecodeError
      end

      it 'wrong key and verify = false should not raise JWT::DecodeError' do
        expect do
          JWT.decode data[alg], wrong_key, false
        end.not_to raise_error
      end
    end
  end

  context 'Invalid' do
    it 'algorithm should raise NotImplementedError' do
      expect do
        JWT.encode payload, 'secret', 'HS255'
      end.to raise_error NotImplementedError
    end

    it 'ECDSA curve_name should raise JWT::IncorrectAlgorithm' do
      key = OpenSSL::PKey::EC.new 'secp256k1'
      key.generate_key

      expect do
        JWT.encode payload, key, 'ES256'
      end.to raise_error JWT::IncorrectAlgorithm

      token = JWT.encode payload, data['ES256_private'], 'ES256'
      key.private_key = nil

      expect do
        JWT.decode token, key
      end.to raise_error JWT::IncorrectAlgorithm
    end
  end

  context 'Verify' do
    context 'algorithm' do
      it 'should raise JWT::IncorrectAlgorithm on missmatch' do
        token = JWT.encode payload, data[:secret], 'HS512'

        expect do
          JWT.decode token, data[:secret], true, algorithm: 'HS384'
        end.to raise_error JWT::IncorrectAlgorithm

        expect do
          JWT.decode token, data[:secret], true, algorithm: 'HS512'
        end.not_to raise_error
      end
    end

    context 'expiration claim' do
      let(:exp) { Time.now.to_i - 5 }
      let(:leeway) { 10 }

      let :token do
        payload.merge!(exp: exp)

        JWT.encode payload, data[:secret]
      end

      it 'old token should raise JWT::ExpiredSignature' do
        expect do
          JWT.decode token, data[:secret]
        end.to raise_error JWT::ExpiredSignature
      end

      it 'should handle leeway' do
        expect do
          JWT.decode token, data[:secret], true, leeway: leeway
        end.not_to raise_error
      end
    end

    context 'not before claim' do
      let(:nbf) { Time.now.to_i + 5 }
      let(:leeway) { 10 }

      let :token do
        payload.merge!(nbf: nbf)

        JWT.encode payload, data[:secret]
      end

      it 'future token should raise JWT::ImmatureSignature' do
        expect do
          JWT.decode token, data[:secret]
        end.to raise_error JWT::ImmatureSignature
      end

      it 'should handle leeway' do
        expect do
          JWT.decode token, data[:secret], true, leeway: leeway
        end.not_to raise_error
      end
    end

    context 'issuer claim' do
      let(:iss) { 'ruby-jwt-gem' }
      let(:invalid_token) { JWT.encode payload, data[:secret] }

      let :token do
        iss_payload = payload.merge(iss: iss)
        JWT.encode iss_payload, data[:secret]
      end

      it 'if verify_iss is set to false (default option) should not raise JWT::InvalidIssuerError' do
        expect do
          JWT.decode token, data[:secret], true, iss: iss
        end.not_to raise_error
      end

      it 'invalid iss should raise JWT::InvalidIssuerError' do
        expect do
          JWT.decode token, data[:secret], true, iss: 'wrong-issuer', verify_iss: true
        end.to raise_error JWT::InvalidIssuerError
      end

      it 'with missing iss claim should raise JWT::InvalidIssuerError' do
        missing_iss_claim_token = JWT.encode payload, data[:secret]

        expect do
          JWT.decode missing_iss_claim_token, data[:secret], true, verify_iss: true, iss: iss
        end.to raise_error(JWT::InvalidIssuerError, /received <none>/)
      end

      it 'valid iss should not raise JWT::InvalidIssuerError' do
        expect do
          JWT.decode token, data[:secret], true, iss: iss, verify_iss: true
        end.not_to raise_error
      end
    end

    context 'issued at claim' do
      let(:iat) { Time.now.to_i }
      let(:new_payload) { payload.merge(iat: iat) }
      let(:token) { JWT.encode new_payload, data[:secret] }
      let(:invalid_token) { JWT.encode new_payload.merge('iat' => iat + 60), data[:secret] }
      let(:leeway) { 30 }

      it 'invalid iat should raise JWT::InvalidIatError' do
        expect do
          JWT.decode invalid_token, data[:secret], true, verify_iat: true
        end.to raise_error JWT::InvalidIatError
      end

      it 'should accept leeway' do
        expect do
          JWT.decode invalid_token, data[:secret], true, verify_iat: true, leeway: 70
        end.to_not raise_error
      end

      it 'valid iat should not raise JWT::InvalidIatError' do
        expect do
          JWT.decode token, data[:secret], true, verify_iat: true
        end.to_not raise_error
      end
    end

    context 'audience claim' do
      let(:simple_aud) { 'ruby-jwt-audience' }
      let(:array_aud) { %w(ruby-jwt-aud test-aud ruby-ruby-ruby) }

      let :simple_token do
        new_payload = payload.merge('aud' => simple_aud)
        JWT.encode new_payload, data[:secret]
      end

      let :array_token do
        new_payload = payload.merge('aud' => array_aud)
        JWT.encode new_payload, data[:secret]
      end

      it 'invalid aud should raise JWT::InvalidAudError' do
        expect do
          JWT.decode simple_token, data[:secret], true, aud: 'wrong audience', verify_aud: true
        end.to raise_error JWT::InvalidAudError

        expect do
          JWT.decode array_token, data[:secret], true, aud: %w(wrong audience), verify_aud: true
        end.to raise_error JWT::InvalidAudError
      end

      it 'valid aud should not raise JWT::InvalidAudError' do
        expect do
          JWT.decode simple_token, data[:secret], true, 'aud' => simple_aud, :verify_aud => true
        end.to_not raise_error

        expect do
          JWT.decode array_token, data[:secret], true, 'aud' => array_aud.first, :verify_aud => true
        end.to_not raise_error
      end
    end

    context 'subject claim' do
      let(:sub) { 'ruby jwt subject' }

      let :token do
        new_payload = payload.merge('sub' => sub)
        JWT.encode new_payload, data[:secret]
      end

      let :invalid_token do
        new_payload = payload.merge('sub' => 'we are not the druids you are looking for')
        JWT.encode new_payload, data[:secret]
      end

      it 'invalid sub should raise JWT::InvalidSubError' do
        expect do
          JWT.decode invalid_token, data[:secret], true, sub: sub, verify_sub: true
        end.to raise_error JWT::InvalidSubError
      end

      it 'valid sub should not raise JWT::InvalidSubError' do
        expect do
          JWT.decode token, data[:secret], true, 'sub' => sub, :verify_sub => true
        end.to_not raise_error
      end
    end

    context 'jwt id claim' do
      let :jti do
        new_payload = payload.merge('iat' => Time.now.to_i)
        key = data[:secret]
        new_payload.merge('jti' => Digest::MD5.hexdigest("#{key}:#{new_payload['iat']}"))
      end

      let(:token) { JWT.encode jti, data[:secret] }

      let :invalid_token do
        jti.delete('iat')
        JWT.encode jti, data[:secret]
      end

      it 'invalid jti should raise JWT::InvalidJtiError' do
        expect do
          JWT.decode invalid_token, data[:secret], true, :verify_jti => true, 'jti' => jti['jti']
        end.to raise_error JWT::InvalidJtiError
      end

      it 'valid jti should not raise JWT::InvalidJtiError' do
        expect do
          JWT.decode token, data[:secret], true, verify_jti: true, jti: jti['jti']
        end.to_not raise_error
      end
    end
  end

  context 'Base64' do
    it 'urlsafe replace + / with - _' do
      allow(Base64).to receive(:encode64) { 'string+with/non+url-safe/characters_' }
      expect(JWT.base64url_encode('foo')).to eq('string-with_non-url-safe_characters_')
    end
  end

  describe 'secure comparison' do
    it 'returns true if strings are equal' do
      expect(JWT.secure_compare('Foo', 'Foo')).to eq true
    end

    it 'returns false if either input is nil or empty' do
      [nil, ''].each do |bad|
        expect(JWT.secure_compare(bad, 'Foo')).to eq false
        expect(JWT.secure_compare('Foo', bad)).to eq false
      end
    end

    it 'retuns false if the strings are different' do
      expect(JWT.secure_compare('Foo', 'Bar')).to eq false
    end
  end

end
