# frozen_string_literal: true

require 'rspec'
require 'simplecov'
require 'jwt'

puts "OpenSSL::VERSION: #{OpenSSL::VERSION}"
puts "OpenSSL::OPENSSL_VERSION: #{OpenSSL::OPENSSL_VERSION}"
puts "OpenSSL::OPENSSL_LIBRARY_VERSION: #{OpenSSL::OPENSSL_LIBRARY_VERSION}\n\n"

CERT_PATH = File.join(__dir__, 'fixtures', 'certs')

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
  config.before(:example) { JWT.configuration.reset! }
  config.run_all_when_everything_filtered = true
  config.filter_run :focus
  config.order = 'random'
end
