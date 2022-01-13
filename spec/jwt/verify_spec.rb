# frozen_string_literal: true

RSpec.describe ::JWT::Verify do
  let(:base_payload) { { 'user_id' => 'some@user.tld' } }
  let(:options) { { leeway: 0 } }

  context '.verify_aud(payload, options)' do
    let(:scalar_aud) { 'ruby-jwt-aud' }
    let(:array_aud) { %w[ruby-jwt-aud test-aud ruby-ruby-ruby] }
    let(:scalar_payload) { base_payload.merge('aud' => scalar_aud) }
    let(:array_payload) { base_payload.merge('aud' => array_aud) }

    it 'must raise JWT::InvalidAudError when the singular audience does not match' do
      expect do
        described_class.verify_aud(scalar_payload, options.merge(aud: 'no-match'))
      end.to raise_error JWT::InvalidAudError
    end

    it 'must raise JWT::InvalidAudError when the payload has an array and none match the supplied value' do
      expect do
        described_class.verify_aud(array_payload, options.merge(aud: 'no-match'))
      end.to raise_error JWT::InvalidAudError
    end

    it 'must allow a matching singular audience to pass' do
      described_class.verify_aud(scalar_payload, options.merge(aud: scalar_aud))
    end

    it 'must allow an array with any value matching the one in the options' do
      described_class.verify_aud(array_payload, options.merge(aud: array_aud.first))
    end

    it 'must allow an array with any value matching any value in the options array' do
      described_class.verify_aud(array_payload, options.merge(aud: array_aud))
    end

    it 'must allow a singular audience payload matching any value in the options array' do
      described_class.verify_aud(scalar_payload, options.merge(aud: array_aud))
    end
  end

  context '.verify_expiration(payload, options)' do
    let(:payload) { base_payload.merge('exp' => (Time.now.to_i - 5)) }

    it 'must raise JWT::ExpiredSignature when the token has expired' do
      expect do
        described_class.verify_expiration(payload, options)
      end.to raise_error JWT::ExpiredSignature
    end

    it 'must allow some leeway in the expiration when global leeway is configured' do
      described_class.verify_expiration(payload, options.merge(leeway: 10))
    end

    it 'must allow some leeway in the expiration when exp_leeway is configured' do
      described_class.verify_expiration(payload, options.merge(exp_leeway: 10))
    end

    it 'must be expired if the exp claim equals the current time' do
      payload['exp'] = Time.now.to_i

      expect do
        described_class.verify_expiration(payload, options)
      end.to raise_error JWT::ExpiredSignature
    end

    context 'when leeway is not specified' do
      let(:options) { {} }

      it 'used a default leeway of 0' do
        expect do
          described_class.verify_expiration(payload, options)
        end.to raise_error JWT::ExpiredSignature
      end
    end
  end

  context '.verify_iat(payload, options)' do
    let(:iat) { Time.now.to_f }
    let(:payload) { base_payload.merge('iat' => iat) }

    it 'must allow a valid iat' do
      described_class.verify_iat(payload, options)
    end

    it 'must ignore configured leeway' do
      expect { described_class.verify_iat(payload.merge('iat' => (iat + 60)), options.merge(leeway: 70)) }
        .to raise_error(JWT::InvalidIatError)
    end

    it 'must properly handle integer times' do
      described_class.verify_iat(payload.merge('iat' => Time.now.to_i), options)
    end

    it 'must raise JWT::InvalidIatError when the iat value is not Numeric' do
      expect do
        described_class.verify_iat(payload.merge('iat' => 'not a number'), options)
      end.to raise_error JWT::InvalidIatError
    end

    it 'must raise JWT::InvalidIatError when the iat value is in the future' do
      expect do
        described_class.verify_iat(payload.merge('iat' => (iat + 120)), options)
      end.to raise_error JWT::InvalidIatError
    end
  end

  context '.verify_iss(payload, options)' do
    let(:iss) { 'ruby-jwt-gem' }
    let(:payload) { base_payload.merge('iss' => iss) }

    let(:invalid_token) { JWT.encode base_payload, payload[:secret] }

    context 'when iss is a String' do
      it 'must raise JWT::InvalidIssuerError when the configured issuer does not match the payload issuer' do
        expect do
          described_class.verify_iss(payload, options.merge(iss: 'mismatched-issuer'))
        end.to raise_error JWT::InvalidIssuerError
      end

      it 'must raise JWT::InvalidIssuerError when the payload does not include an issuer' do
        expect do
          described_class.verify_iss(base_payload, options.merge(iss: iss))
        end.to raise_error(JWT::InvalidIssuerError, /received <none>/)
      end

      it 'must allow a matching issuer to pass' do
        described_class.verify_iss(payload, options.merge(iss: iss))
      end
    end
    context 'when iss is an Array' do
      it 'must raise JWT::InvalidIssuerError when no matching issuers in array' do
        expect do
          described_class.verify_iss(payload, options.merge(iss: %w[first second]))
        end.to raise_error JWT::InvalidIssuerError
      end

      it 'must raise JWT::InvalidIssuerError when the payload does not include an issuer' do
        expect do
          described_class.verify_iss(base_payload, options.merge(iss: %w[first second]))
        end.to raise_error(JWT::InvalidIssuerError, /received <none>/)
      end

      it 'must allow an array with matching issuer to pass' do
        described_class.verify_iss(payload, options.merge(iss: ['first', iss, 'third']))
      end
    end
    context 'when iss is a RegExp' do
      it 'must raise JWT::InvalidIssuerError when the regular expression does not match' do
        expect do
          described_class.verify_iss(payload, options.merge(iss: /\A(first|second)\z/))
        end.to raise_error JWT::InvalidIssuerError
      end

      it 'must raise JWT::InvalidIssuerError when the payload does not include an issuer' do
        expect do
          described_class.verify_iss(base_payload, options.merge(iss: /\A(first|second)\z/))
        end.to raise_error(JWT::InvalidIssuerError, /received <none>/)
      end

      it 'must allow a regular expression matching the issuer to pass' do
        described_class.verify_iss(payload, options.merge(iss: /\A(first|#{iss}|third)\z/))
      end
    end
    context 'when iss is a Proc' do
      it 'must raise JWT::InvalidIssuerError when the proc returns false' do
        expect do
          described_class.verify_iss(payload, options.merge(iss: ->(iss) { iss && iss.start_with?('first') }))
        end.to raise_error JWT::InvalidIssuerError
      end

      it 'must raise JWT::InvalidIssuerError when the payload does not include an issuer' do
        expect do
          described_class.verify_iss(base_payload, options.merge(iss: ->(iss) { iss && iss.start_with?('first') }))
        end.to raise_error(JWT::InvalidIssuerError, /received <none>/)
      end

      it 'must allow a proc that returns true to pass' do
        described_class.verify_iss(payload, options.merge(iss: ->(iss) { iss && iss.start_with?('ruby') }))
      end
    end
    context 'when iss is a Method instance' do
      def issuer_start_with_first?(issuer)
        issuer&.start_with?('first')
      end

      def issuer_start_with_ruby?(issuer)
        issuer&.start_with?('ruby')
      end

      it 'must raise JWT::InvalidIssuerError when the method returns false' do
        expect do
          described_class.verify_iss(payload, options.merge(iss: method(:issuer_start_with_first?)))
        end.to raise_error JWT::InvalidIssuerError
      end

      it 'must raise JWT::InvalidIssuerError when the payload does not include an issuer' do
        expect do
          described_class.verify_iss(base_payload, options.merge(iss: method(:issuer_start_with_first?)))
        end.to raise_error(JWT::InvalidIssuerError, /received <none>/)
      end

      it 'must allow a method that returns true to pass' do
        described_class.verify_iss(payload, options.merge(iss: method(:issuer_start_with_ruby?)))
      end
    end
  end

  context '.verify_jti(payload, options)' do
    let(:payload) { base_payload.merge('jti' => 'some-random-uuid-or-whatever') }

    it 'must allow any jti when the verfy_jti key in the options is truthy but not a proc' do
      described_class.verify_jti(payload, options.merge(verify_jti: true))
    end

    it 'must raise JWT::InvalidJtiError when the jti is missing' do
      expect do
        described_class.verify_jti(base_payload, options)
      end.to raise_error JWT::InvalidJtiError, /missing/i
    end

    it 'must raise JWT::InvalidJtiError when the jti is an empty string' do
      expect do
        described_class.verify_jti(base_payload.merge('jti' => '   '), options)
      end.to raise_error JWT::InvalidJtiError, /missing/i
    end

    it 'must raise JWT::InvalidJtiError when verify_jti proc returns false' do
      expect do
        described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti) { false }))
      end.to raise_error JWT::InvalidJtiError, /invalid/i
    end

    it 'true proc should not raise JWT::InvalidJtiError' do
      described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti) { true }))
    end

    it 'it should not throw arguement error with 2 args' do
      expect do
        described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti, _pl) {
          true
        }))
      end.to_not raise_error
    end
    it 'should have payload as second param in proc' do
      described_class.verify_jti(payload, options.merge(verify_jti: ->(_jti, pl) {
        expect(pl).to eq(payload)
      }))
    end
  end

  context '.verify_not_before(payload, options)' do
    let(:payload) { base_payload.merge('nbf' => (Time.now.to_i + 5)) }

    it 'must raise JWT::ImmatureSignature when the nbf in the payload is in the future' do
      expect do
        described_class.verify_not_before(payload, options)
      end.to raise_error JWT::ImmatureSignature
    end

    it 'must allow some leeway in the token age when global leeway is configured' do
      described_class.verify_not_before(payload, options.merge(leeway: 10))
    end

    it 'must allow some leeway in the token age when nbf_leeway is configured' do
      described_class.verify_not_before(payload, options.merge(nbf_leeway: 10))
    end
  end

  context '.verify_sub(payload, options)' do
    let(:sub) { 'ruby jwt subject' }

    it 'must raise JWT::InvalidSubError when the subjects do not match' do
      expect do
        described_class.verify_sub(base_payload.merge('sub' => 'not-a-match'), options.merge(sub: sub))
      end.to raise_error JWT::InvalidSubError
    end

    it 'must allow a matching sub' do
      described_class.verify_sub(base_payload.merge('sub' => sub), options.merge(sub: sub))
    end
  end

  context '.verify_claims' do
    let(:fail_verifications_options) { { iss: 'mismatched-issuer', aud: 'no-match', sub: 'some subject' } }
    let(:fail_verifications_payload) {
      {
        'exp' => (Time.now.to_i - 50),
        'jti' => '   ',
        'iss' => 'some-issuer',
        'nbf' => (Time.now.to_i + 50),
        'iat' => 'not a number',
        'sub' => 'not-a-match'
      }
    }

    %w[verify_aud verify_expiration verify_iat verify_iss verify_jti verify_not_before verify_sub].each do |method|
      let(:payload) { base_payload.merge(fail_verifications_payload) }
      it "must skip verification when #{method} option is set to false" do
        described_class.verify_claims(payload, options.merge(method => false))
      end

      it "must raise error when #{method} option is set to true" do
        expect do
          described_class.verify_claims(payload, options.merge(method => true).merge(fail_verifications_options))
        end.to raise_error JWT::DecodeError
      end
    end
  end

  context '.verify_required_claims(payload, options)' do
    it 'must raise JWT::MissingRequiredClaim if a required claim is absent' do
      expect do
        described_class.verify_required_claims(base_payload, options.merge(required_claims: ['exp']))
      end.to raise_error JWT::MissingRequiredClaim
    end

    it 'must verify the claims if all required claims are present' do
      payload = base_payload.merge('exp' => (Time.now.to_i + 5), 'custom_claim' => true)
      described_class.verify_required_claims(payload, options.merge(required_claims: ['exp', 'custom_claim']))
    end
  end
end
