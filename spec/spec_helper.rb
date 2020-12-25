# frozen_string_literal: true

require 'rspec'
require 'simplecov'
require 'simplecov-json'
require 'codeclimate-test-reporter'

SimpleCov.start do
  root File.join(File.dirname(__FILE__), '..')
  project_name 'Ruby JWT - Ruby JSON Web Token implementation'
  add_filter 'spec'
end

require 'jwt'

CERT_PATH = File.join(File.dirname(__FILE__), 'fixtures', 'certs')

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.run_all_when_everything_filtered = true
  config.filter_run :focus
  config.order = 'random'
end
