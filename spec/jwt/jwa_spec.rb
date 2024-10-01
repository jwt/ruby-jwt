# frozen_string_literal: true

RSpec.describe JWT::JWA do
  describe '.create' do
    describe 'Backwards compatibility' do
      describe 'create, sign and verify' do
        it 'finds an algorithm with old api' do
          alg = described_class.create('HS256')
          signature = alg.sign(data: 'data', signing_key: 'key')
          expect(signature).to be_a(String)
          expect(alg.verify(data: 'data', signature: signature, verification_key: 'key')).to be(true)
        end
      end
    end
  end
end
