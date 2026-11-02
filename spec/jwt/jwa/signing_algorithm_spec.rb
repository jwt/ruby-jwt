# frozen_string_literal: true

RSpec.describe JWT::JWA::SigningAlgorithm do
  let(:payload) { { 'user_id' => 'some@user.tld' } }

  let(:custom_algorithm) do
    Class.new do
      include JWT::JWA::SigningAlgorithm

      def initialize(signature: 'custom_signature', alg: 'custom')
        @signature = signature
        @alg       = alg
      end

      def sign(*)
        @signature
      end

      def verify(data:, signature:, verification_key:) # rubocop:disable Lint/UnusedMethodArgument
        signature == @signature
      end
    end
  end

  let(:token) { JWT.encode(payload, 'secret', custom_algorithm.new) }
  let(:expected_token) { 'eyJhbGciOiJjdXN0b20ifQ.eyJ1c2VyX2lkIjoic29tZUB1c2VyLnRsZCJ9.Y3VzdG9tX3NpZ25hdHVyZQ' }

  it 'can be used for encoding' do
    expect(token).to eq(expected_token)
  end

  it 'can be used for decoding' do
    expect(JWT.decode(token, 'secret', true, algorithm: custom_algorithm.new)).to eq([payload, { 'alg' => 'custom' }])
  end

  context 'when multiple custom algorithms are given for decoding' do
    it 'tries until the first match' do
      expect(JWT.decode(token, 'secret', true, algorithms: [custom_algorithm.new(signature: 'not_this'), custom_algorithm.new])).to eq([payload, { 'alg' => 'custom' }])
    end
  end

  context 'when class has custom header method' do
    before do
      custom_algorithm.class_eval do
        def header(*)
          { 'alg' => alg, 'foo' => 'bar' }
        end
      end
    end

    it 'uses the provided header' do
      expect(JWT.decode(token, 'secret', true, algorithm: custom_algorithm.new)).to eq([payload, { 'alg' => 'custom', 'foo' => 'bar' }])
    end
  end

  context 'when class is not utilizing the ::JWT::JWA::SigningAlgorithm module' do
    let(:custom_algorithm) do
      Class.new do
        attr_reader :alg

        def initialize(signature: 'custom_signature', alg: 'custom')
          @signature = signature
          @alg       = alg
        end

        def header(*)
          { 'alg' => @alg, 'foo' => 'bar' }
        end

        def sign(*)
          @signature
        end

        def verify(*)
          true
        end
      end
    end

    it 'raises an error' do
      expect { token }.to raise_error(ArgumentError, 'Custom algorithms are required to include JWT::JWA::SigningAlgorithm')
    end
  end

  context 'when alg is not matching' do
    it 'fails the validation process' do
      expect { JWT.decode(token, 'secret', true, algorithms: custom_algorithm.new(alg: 'not_a_match')) }.to raise_error(JWT::IncorrectAlgorithm, 'Expected a different algorithm')
    end
  end

  context 'when signature is not matching' do
    it 'fails the validation process' do
      expect { JWT.decode(token, 'secret', true, algorithms: custom_algorithm.new(signature: 'not_a_match')) }.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end
  end

  context 'when #sign method is missing' do
    before do
      custom_algorithm.instance_eval do
        remove_method :sign
      end
    end

    it 'raises an error on encoding' do
      expect { token }.to raise_error(JWT::EncodeError, /missing the sign method/)
    end

    it 'allows decoding' do
      expect(JWT.decode(expected_token, 'secret', true, algorithm: custom_algorithm.new)).to eq([payload, { 'alg' => 'custom' }])
    end
  end

  context 'when #verify method is missing' do
    before do
      custom_algorithm.instance_eval do
        remove_method :verify
      end
    end

    it 'can be used for encoding' do
      expect(token).to eq(expected_token)
    end

    it 'raises error on decoding' do
      expect { JWT.decode(expected_token, 'secret', true, algorithm: custom_algorithm.new) }.to raise_error(JWT::VerificationKeyError, /missing the verify method/)
    end
  end
end
