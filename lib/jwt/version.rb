# frozen_string_literal: true

# Moments version builder module
module JWT
  def self.gem_version
    Gem::Version.new VERSION::STRING
  end

  # Moments version builder module
  module VERSION
    # major version
    MAJOR = 2
    # minor version
    MINOR = 5
    # tiny version
    TINY  = 0
    # alpha, beta, etc. tag
    PRE   = nil

    # Build version string
    STRING = [MAJOR, MINOR, TINY, PRE].compact.join('.')
  end

  def self.openssl_3?
    return false if OpenSSL::OPENSSL_VERSION.include?('LibreSSL')
    return true if OpenSSL::OPENSSL_VERSION_NUMBER >= 3 * 0x10000000
  end

  def self.openssl_3_hmac_empty_key_regression?
    openssl_3? && ::Gem::Version.new(OpenSSL::VERSION) <= ::Gem::Version.new('3.0.0')
  end
end
