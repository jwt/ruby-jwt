# frozen_string_literal: true

require 'openssl'
require 'simplecov_json_formatter'

SimpleCov.start do
  command_name "Job #{File.basename(ENV['BUNDLE_GEMFILE'])}" if ENV['BUNDLE_GEMFILE']
  project_name 'Ruby JWT - Ruby JSON Web Token implementation'
  coverage_dir "coverage-#{OpenSSL::Digest::SHA256.hexdigest(ENV['GITHUB_STEP_SUMMARY'])}" if ENV['GITHUB_STEP_SUMMARY']
  add_filter 'spec'
end

SimpleCov.formatters = SimpleCov::Formatter::JSONFormatter if ENV['CI']
