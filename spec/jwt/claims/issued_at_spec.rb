# frozen_string_literal: true

RSpec.describe JWT::Claims::IssuedAt do
  let(:payload) { { 'iat' => Time.now.to_f } }

  subject(:validate!) { described_class.new.validate!(context: Struct.new(:payload).new(payload)) }

  context 'when iat is now' do
    it 'passes validation' do
      validate!
    end
  end

  context 'when iat is now as a integer' do
    let(:payload) { { 'iat' => Time.now.to_i } }

    it 'passes validation' do
      validate!
    end
  end
  context 'when iat is not a number' do
    let(:payload) { { 'iat' => 'not_a_number' } }

    it 'fails validation' do
      expect { validate! }.to raise_error(JWT::InvalidIatError)
    end
  end

  context 'when iat is in the future' do
    let(:payload) { { 'iat' => Time.now.to_f + 120.0 } }

    it 'fails validation' do
      expect { validate! }.to raise_error(JWT::InvalidIatError)
    end
  end

  context 'when payload is a string containing iat' do
    let(:payload) { 'beautyexperts_nbf_iat' }

    it 'passes validation' do
      validate!
    end
  end
end
