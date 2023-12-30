# frozen_string_literal: true

module SpecSupport
  module TestKeys
    KEY_FIXTURE_PATH = File.join(__dir__, '..', 'fixtures', 'keys')

    def test_pkey(key)
      TestKeys.keys[key] ||= read_pkey(key)
    end

    def read_pkey(key)
      OpenSSL::PKey.read(File.read(File.join(KEY_FIXTURE_PATH, key)))
    end

    def self.keys
      @keys ||= {}
    end
  end
end
