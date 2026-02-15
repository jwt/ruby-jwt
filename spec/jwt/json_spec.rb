# frozen_string_literal: true

RSpec.describe JWT::JSON do
  describe '.generate' do
    it 'generates JSON from a hash' do
      expect(described_class.generate({ 'a' => 1 })).to eq('{"a":1}')
    end
  end

  describe '.parse' do
    context 'with allow_duplicate_keys: true (default)' do
      it 'uses the last value for duplicate keys' do
        result = described_class.parse('{"a":1,"a":2}')
        expect(result['a']).to eq(2)
      end

      it 'parses valid JSON without duplicates' do
        result = described_class.parse('{"a":1,"b":2}')
        expect(result).to eq({ 'a' => 1, 'b' => 2 })
      end
    end

    context 'with allow_duplicate_keys: false' do
      context 'when JSON gem supports duplicate key detection', if: JWT::JSON.supports_duplicate_key_detection? do
        it 'raises DuplicateKeyError for duplicate keys' do
          expect do
            described_class.parse('{"a":1,"a":2}', allow_duplicate_keys: false)
          end.to raise_error(JWT::DuplicateKeyError, /duplicate key/)
        end

        it 'parses valid JSON without duplicates' do
          result = described_class.parse('{"a":1,"b":2}', allow_duplicate_keys: false)
          expect(result).to eq({ 'a' => 1, 'b' => 2 })
        end

        it 'detects duplicates in nested objects' do
          json = '{"outer":{"inner":1,"inner":2}}'
          expect do
            described_class.parse(json, allow_duplicate_keys: false)
          end.to raise_error(JWT::DuplicateKeyError, /duplicate key/)
        end

        it 'allows same key in different objects' do
          json = '{"obj1":{"a":1},"obj2":{"a":2}}'
          result = described_class.parse(json, allow_duplicate_keys: false)
          expect(result['obj1']['a']).to eq(1)
          expect(result['obj2']['a']).to eq(2)
        end
      end

      context 'when JSON gem does not support duplicate key detection', unless: JWT::JSON.supports_duplicate_key_detection? do
        it 'silently allows duplicate keys (uses last value)' do
          result = described_class.parse('{"a":1,"a":2}', allow_duplicate_keys: false)
          expect(result['a']).to eq(2)
        end
      end
    end
  end
end
