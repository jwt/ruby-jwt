# frozen_string_literal: true

RSpec.describe 'Custom Signing algorithm' do
  let(:payload) { { 'pay' => 'load'} }

  let(:signing_algo) do
    Class.new do
      class << self
        def alg
          'CustomStatic'
        end

        def valid_alg?(algorithm_from_header)
          algorithm_from_header == self.alg
        end

        def sign(_to_sign, _options)
          'static'
        end

        def verify(_to_verify, signature, _options)
          signature == 'static'
        end
      end
    end
  end

  subject(:extension) do
    algo = signing_algo

    Class.new do
      include JWT
      algorithm algo
    end
  end

  context 'when encoding' do
    it 'adds the custom signature to the end' do
      expect(::Base64.decode64(subject.encode!(payload).split('.')[2])).to eq('static')
    end
  end

  context 'when decoding signed token' do
    let(:presigned_token) { subject.encode!(payload) }
    it 'verifies and decodes the payload' do
      expect(subject.decode!(presigned_token)).to eq([{'pay' => 'load'}, {'alg' => 'CustomStatic'}])
    end
  end
end
