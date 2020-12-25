# frozen_string_literal: true

RSpec.describe JWT::ClaimsValidator do
  let(:validator) { described_class.new(claims) }

  describe '#validate!' do
    subject { validator.validate! }

    shared_examples_for 'a NumericDate claim' do |claim|
      context "when #{claim} payload is an integer" do
        let(:claims) { { claim => 12345 } }

        it 'does not raise error' do
          expect { subject }.not_to raise_error
        end

        context 'and key is a string' do
          let(:claims) { { claim.to_s => 43.32 } }

          it 'does not raise error' do
            expect { subject }.not_to raise_error
          end
        end
      end

      context "when #{claim} payload is a float" do
        let(:claims) { { claim => 43.32 } }

        it 'does not raise error' do
          expect { subject }.not_to raise_error
        end
      end

      context "when #{claim} payload is a string" do
        let(:claims) { { claim => '1' } }

        it 'raises error' do
          expect { subject }.to raise_error JWT::InvalidPayload
        end

        context 'and key is a string' do
          let(:claims) { { claim.to_s => '1' } }

          it 'raises error' do
            expect { subject }.to raise_error JWT::InvalidPayload
          end
        end
      end

      context "when #{claim} payload is a Time object" do
        let(:claims) { { claim => Time.now } }

        it 'raises error' do
          expect { subject }.to raise_error JWT::InvalidPayload
        end
      end

      context "when #{claim} payload is a string" do
        let(:claims) { { claim => '1' } }

        it 'raises error' do
          expect { subject }.to raise_error JWT::InvalidPayload
        end
      end
    end

    context 'exp claim' do
      it_should_behave_like 'a NumericDate claim', :exp
    end

    context 'iat claim' do
      it_should_behave_like 'a NumericDate claim', :iat
    end

    context 'nbf claim' do
      it_should_behave_like 'a NumericDate claim', :nbf
    end
  end
end
