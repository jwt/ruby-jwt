# frozen_string_literal: true
require 'spec_helper'
require 'jwt/verify'

module JWT
  RSpec.describe Verify do
    let(:base_payload) { { 'user_id' => 'some@user.tld' } }
    let(:options) { { leeway: 0 } }

    context '.verify_aud(payload, options)' do
      let(:scalar_aud) { 'ruby-jwt-audience' }
      let(:array_aud) { %w(ruby-jwt-aud test-aud ruby-ruby-ruby) }
      let(:scalar_payload) { base_payload.merge('aud' => scalar_aud) }
      let(:array_payload) { base_payload.merge('aud' => array_aud) }

      it 'must raise JWT::InvalidAudError when the singular audience does not match' do
        expect do
          Verify.verify_aud(scalar_payload, options.merge(aud: 'no-match'))
        end.to raise_error JWT::InvalidAudError
      end

      it 'must raise JWT::InvalidAudError when the payload has an array and none match the supplied value' do
        expect do
          Verify.verify_aud(array_payload, options.merge(aud: 'no-match'))
        end.to raise_error JWT::InvalidAudError
      end

      it 'must raise JWT::InvalidAudError when the singular audience does not match and the options aud key is a string' do
        expect do
          Verify.verify_aud(scalar_payload, options.merge('aud' => 'no-match'))
        end.to raise_error JWT::InvalidAudError
      end

      it 'must allow a matching singular audience to pass' do
        Verify.verify_aud(scalar_payload, options.merge(aud: scalar_aud))
      end

      it 'must allow a matching audence to pass when the options key is a string' do
        Verify.verify_aud(scalar_payload, options.merge('aud' => scalar_aud))
      end

      it 'must allow an array with any value matching the one in the options' do
        Verify.verify_aud(array_payload, options.merge(aud: array_aud.first))
      end

      it 'must allow an array with any value matching the one in the options with a string options key' do
        Verify.verify_aud(array_payload, options.merge('aud' => array_aud.first))
      end

      it 'should allow strings or symbolds in options array' do
        options['aud'] = [
          'ruby-jwt-aud', 
          'test-aud',
          'ruby-ruby-ruby',
          :test
        ]

        array_payload['aud'].push('test')
        
        Verify.verify_aud(array_payload, options)
      end
    end

    context '.verify_expiration(payload, options)' do
      let(:leeway) { 10 }
      let(:payload) { base_payload.merge('exp' => (Time.now.to_i - 5)) }

      it 'must raise JWT::ExpiredSignature when the token has expired' do
        expect do
          Verify.verify_expiration(payload, options)
        end.to raise_error JWT::ExpiredSignature
      end

      it 'must allow some leeway in the expiration when configured' do
        Verify.verify_expiration(payload, options.merge(leeway: 10))
      end

      it 'must be expired if the exp claim equals the current time' do
        payload['exp'] = Time.now.to_i

        expect do
          Verify.verify_expiration(payload, options)
        end.to raise_error JWT::ExpiredSignature
      end
    end

    context '.verify_iat(payload, options)' do
      let(:iat) { Time.now.to_f }
      let(:payload) { base_payload.merge('iat' => iat) }

      it 'must allow a valid iat' do
        Verify.verify_iat(payload, options)
      end

      it 'must allow configured leeway' do
        Verify.verify_iat(payload.merge('iat' => (iat + 60)), options.merge(leeway: 70))
      end

      it 'must properly handle integer times' do
        Verify.verify_iat(payload.merge('iat' => Time.now.to_i), options)
      end

      it 'must raise JWT::InvalidIatError when the iat value is not Numeric' do
        expect do
          Verify.verify_iat(payload.merge('iat' => 'not a number'), options)
        end.to raise_error JWT::InvalidIatError
      end

      it 'must raise JWT::InvalidIatError when the iat value is in the future' do
        expect do
          Verify.verify_iat(payload.merge('iat' => (iat + 120)), options)
        end.to raise_error JWT::InvalidIatError
      end
    end

    context '.verify_iss(payload, options)' do
      let(:iss) { 'ruby-jwt-gem' }
      let(:payload) { base_payload.merge('iss' => iss) }

      let(:invalid_token) { JWT.encode base_payload, payload[:secret] }

      it 'must raise JWT::InvalidIssuerError when the configured issuer does not match the payload issuer' do
        expect do
          Verify.verify_iss(payload, options.merge(iss: 'mismatched-issuer'))
        end.to raise_error JWT::InvalidIssuerError
      end

      it 'must raise JWT::InvalidIssuerError when the payload does not include an issuer' do
        expect do
          Verify.verify_iss(base_payload, options.merge(iss: iss))
        end.to raise_error(JWT::InvalidIssuerError, /received <none>/)
      end

      it 'must allow a matching issuer to pass' do
        Verify.verify_iss(payload, options.merge(iss: iss))
      end
    end

    context '.verify_jti(payload, options)' do
      let(:payload) { base_payload.merge('jti' => 'some-random-uuid-or-whatever') }

      it 'must allow any jti when the verfy_jti key in the options is truthy but not a proc' do
        Verify.verify_jti(payload, options.merge(verify_jti: true))
      end

      it 'must raise JWT::InvalidJtiError when the jti is missing' do
        expect do
          Verify.verify_jti(base_payload, options)
        end.to raise_error JWT::InvalidJtiError, /missing/i
      end

      it 'must raise JWT::InvalidJtiError when the jti is an empty string' do
        expect do
          Verify.verify_jti(base_payload.merge('jti' => '   '), options)
        end.to raise_error JWT::InvalidJtiError, /missing/i
      end

      it 'must raise JWT::InvalidJtiError when verify_jti proc returns false' do
        expect do
          Verify.verify_jti(payload, options.merge(verify_jti: ->(_jti) { false }))
        end.to raise_error JWT::InvalidJtiError, /invalid/i
      end

      it 'true proc should not raise JWT::InvalidJtiError' do
        Verify.verify_jti(payload, options.merge(verify_jti: ->(_jti) { true }))
      end
    end

    context '.verify_not_before(payload, options)' do
      let(:payload) { base_payload.merge('nbf' => (Time.now.to_i + 5)) }

      it 'must raise JWT::ImmatureSignature when the nbf in the payload is in the future' do
        expect do
          Verify.verify_not_before(payload, options)
        end.to raise_error JWT::ImmatureSignature
      end

      it 'must allow some leeway in the token age when configured' do
        Verify.verify_not_before(payload, options.merge(leeway: 10))
      end
    end

    context '.verify_sub(payload, options)' do
      let(:sub) { 'ruby jwt subject' }

      it 'must raise JWT::InvalidSubError when the subjects do not match' do
        expect do
          Verify.verify_sub(base_payload.merge('sub' => 'not-a-match'), options.merge(sub: sub))
        end.to raise_error JWT::InvalidSubError
      end

      it 'must allow a matching sub' do
        Verify.verify_sub(base_payload.merge('sub' => sub), options.merge(sub: sub))
      end
    end
  end
end
