# frozen_string_literal: true

RSpec.describe JWT::Configuration::JwkConfiguration do
  describe '.kid_generator_type=' do
    context 'when invalid value is passed' do
      it 'raises ArgumentError' do
        expect { subject.kid_generator_type = :foo }.to raise_error(ArgumentError, 'foo is not a valid kid generator type.')
      end
    end

    context 'when valid value is passed' do
      it 'sets the generator matching the value' do
        subject.kid_generator_type = :rfc7638_thumbprint
        expect(subject.kid_generator).to eq(JWT::JWK::Thumbprint)
      end
    end
  end
end
