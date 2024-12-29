# frozen_string_literal: true

RSpec.describe JWT do
  describe '.gem_version' do
    it 'returns the gem version' do
      expect(described_class.gem_version).to eq(Gem::Version.new(JWT::VERSION::STRING))
    end
  end
  describe 'VERSION constants' do
    it 'has a MAJOR version' do
      expect(JWT::VERSION::MAJOR).to be_a(Integer)
    end

    it 'has a MINOR version' do
      expect(JWT::VERSION::MINOR).to be_a(Integer)
    end

    it 'has a TINY version' do
      expect(JWT::VERSION::TINY).to be_a(Integer)
    end

    it 'has a PRE version' do
      expect(JWT::VERSION::PRE).to be_a(String).or be_nil
    end

    it 'has a STRING version' do
      expect(JWT::VERSION::STRING).to be_a(String)
    end
  end
end
