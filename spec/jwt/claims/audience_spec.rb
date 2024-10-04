# frozen_string_literal: true

RSpec.describe JWT::Claims::Audience do
  let(:payload) { { 'nbf' => (Time.now.to_i + 5) } }

  describe '#verify!' do
    let(:scalar_aud) { 'ruby-jwt-aud' }
    let(:array_aud) { %w[ruby-jwt-aud test-aud ruby-ruby-ruby] }

    subject(:verify!) { described_class.new(expected_audience: expected_audience).verify!(context: SpecSupport::Token.new(payload: payload)) }

    context 'when the singular audience does not match' do
      let(:expected_audience) { 'no-match' }
      let(:payload) { { 'aud' => scalar_aud } }

      it 'raises JWT::InvalidAudError' do
        expect do
          subject
        end.to raise_error JWT::InvalidAudError
      end
    end

    context 'when the payload has an array and none match the supplied value' do
      let(:expected_audience) { 'no-match' }
      let(:payload) { { 'aud' => array_aud } }

      it 'raises JWT::InvalidAudError' do
        expect do
          subject
        end.to raise_error JWT::InvalidAudError
      end
    end

    context 'when single audience is required' do
      let(:expected_audience) { scalar_aud }
      let(:payload) { { 'aud' => scalar_aud } }

      it 'passes validation' do
        subject
      end
    end

    context 'when any value in payload matches a single expected' do
      let(:expected_audience) { array_aud.first }
      let(:payload) { { 'aud' => array_aud } }

      it 'passes validation' do
        subject
      end
    end

    context 'when an array with any value matching the one in the options' do
      let(:expected_audience) { array_aud.first }
      let(:payload) { { 'aud' => array_aud } }

      it 'passes validation' do
        subject
      end
    end

    context 'when an array with any value matching all in the options' do
      let(:expected_audience) { array_aud }
      let(:payload) { { 'aud' => array_aud } }

      it 'passes validation' do
        subject
      end
    end

    context 'when a singular audience payload matching any value in the options array' do
      let(:expected_audience) { array_aud }
      let(:payload) { { 'aud' => scalar_aud } }

      it 'passes validation' do
        subject
      end
    end
  end
end
