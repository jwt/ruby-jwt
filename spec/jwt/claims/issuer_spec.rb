# frozen_string_literal: true

RSpec.describe JWT::Claims::Issuer do
  let(:issuer) { 'ruby-jwt-gem' }
  let(:payload) { { 'iss' => issuer } }
  let(:expected_issuers) { 'ruby-jwt-gem' }

  subject(:verify!) { described_class.new(issuers: expected_issuers).verify!(context: SpecSupport::Token.new(payload: payload)) }

  context 'when expected issuer is a string that matches the payload' do
    it 'passes validation' do
      verify!
    end
  end

  context 'when expected issuer is a string that does not match the payload' do
    let(:issuer) { 'mismatched-issuer' }
    it 'raises JWT::InvalidIssuerError' do
      expect { verify! }.to raise_error(JWT::InvalidIssuerError, 'Invalid issuer. Expected ["ruby-jwt-gem"], received mismatched-issuer')
    end
  end

  context 'when payload does not contain any issuer' do
    let(:payload) { {} }
    it 'raises JWT::InvalidIssuerError' do
      expect { verify! }.to raise_error(JWT::InvalidIssuerError, 'Invalid issuer. Expected ["ruby-jwt-gem"], received <none>')
    end
  end

  context 'when payload is not a Hash' do
    [['x'], 42, nil, 'iss'].each do |non_hash_payload|
      context "when payload is #{non_hash_payload.inspect}" do
        let(:payload) { non_hash_payload }
        it 'raises JWT::InvalidIssuerError' do
          expect { verify! }.to raise_error(JWT::InvalidIssuerError, 'Invalid issuer. Expected ["ruby-jwt-gem"], received <none>')
        end
      end
    end

    context 'when payload is a String containing the expected issuer' do
      let(:payload) { 'iss' }
      let(:expected_issuers) { 'iss' }
      it 'raises JWT::InvalidIssuerError' do
        expect { verify! }.to raise_error(JWT::InvalidIssuerError, 'Invalid issuer. Expected ["iss"], received <none>')
      end
    end

    context 'when issuer is given as a Proc' do
      let(:payload) { ['x'] }
      let(:expected_issuers) { ->(iss) { iss.start_with?('ruby') } }
      it 'raises JWT::InvalidIssuerError without calling the Proc' do
        expect { verify! }.to raise_error(JWT::InvalidIssuerError, /received <none>/)
      end
    end
  end

  context 'when the issuer is not a String' do
    let(:issuer) { 42 }
    let(:expected_issuers) { ->(iss) { iss.start_with?('ruby') } }
    it 'raises JWT::InvalidIssuerError without calling the Proc' do
      expect { verify! }.to raise_error(JWT::InvalidIssuerError, /received 42\z/)
    end
  end

  context 'when nil is one of the expected issuers' do
    let(:expected_issuers) { [nil] }

    context 'when payload does not contain any issuer' do
      let(:payload) { {} }
      it 'raises JWT::InvalidIssuerError' do
        expect { verify! }.to raise_error(JWT::InvalidIssuerError, 'Invalid issuer. Expected [nil], received <none>')
      end
    end
  end

  context 'when expected issuer is an array that matches the payload' do
    let(:expected_issuers) { ['first', issuer, 'third'] }
    it 'passes validation' do
      verify!
    end
  end

  context 'when expected issuer is an array that does not match the payload' do
    let(:expected_issuers) { %w[first second] }
    it 'raises JWT::InvalidIssuerError' do
      expect { verify! }.to raise_error(JWT::InvalidIssuerError, 'Invalid issuer. Expected ["first", "second"], received ruby-jwt-gem')
    end
  end

  context 'when expected issuer is an array and payload does not have any issuer' do
    let(:payload) { {} }
    let(:expected_issuers) { %w[first second] }
    it 'raises JWT::InvalidIssuerError' do
      expect { verify! }.to raise_error(JWT::InvalidIssuerError, 'Invalid issuer. Expected ["first", "second"], received <none>')
    end
  end

  context 'when issuer is given as a RegExp' do
    let(:issuer) { 'ruby-jwt-gem' }
    let(:expected_issuers) { /\A(first|#{issuer}|third)\z/ }
    it 'passes validation' do
      verify!
    end
  end

  context 'when issuer is given as a RegExp and does not match the payload' do
    let(:issuer) { 'mismatched-issuer' }
    let(:expected_issuers) { /\A(first|second)\z/ }
    it 'raises JWT::InvalidIssuerError' do
      expect { verify! }.to raise_error(JWT::InvalidIssuerError, 'Invalid issuer. Expected [/\A(first|second)\z/], received mismatched-issuer')
    end
  end

  context 'when issuer is given as a RegExp and payload does not have any issuer' do
    let(:payload) { {} }
    let(:expected_issuers) { /\A(first|second)\z/ }
    it 'raises JWT::InvalidIssuerError' do
      expect { verify! }.to raise_error(JWT::InvalidIssuerError, 'Invalid issuer. Expected [/\A(first|second)\z/], received <none>')
    end
  end

  context 'when issuer is given as a Proc' do
    let(:issuer) { 'ruby-jwt-gem' }
    let(:expected_issuers) { ->(iss) { iss.start_with?('ruby') } }
    it 'passes validation' do
      verify!
    end
  end

  context 'when issuer is given as a Proc and does not match the payload' do
    let(:issuer) { 'mismatched-issuer' }
    let(:expected_issuers) { ->(iss) { iss.start_with?('ruby') } }
    it 'raises JWT::InvalidIssuerError' do
      expect { verify! }.to raise_error(JWT::InvalidIssuerError, /received mismatched-issuer/)
    end
  end

  context 'when issuer is given as a Proc and payload does not have any issuer' do
    let(:payload) { {} }
    let(:expected_issuers) { ->(iss) { iss.start_with?('ruby') } }
    it 'raises JWT::InvalidIssuerError without calling the Proc' do
      expect { verify! }.to raise_error(JWT::InvalidIssuerError, /received <none>/)
    end
  end

  context 'when issuer is given as a Proc that accepts a missing issuer' do
    let(:payload) { {} }
    let(:expected_issuers) { lambda(&:nil?) }
    it 'raises JWT::InvalidIssuerError' do
      expect { verify! }.to raise_error(JWT::InvalidIssuerError, /received <none>/)
    end
  end

  context 'when issuer is given as a Method instance' do
    def issuer_start_with_ruby?(issuer)
      issuer&.start_with?('ruby')
    end

    let(:issuer) { 'ruby-jwt-gem' }
    let(:expected_issuers) { method(:issuer_start_with_ruby?) }

    it 'passes validation' do
      verify!
    end
  end
end
