# encoding: utf-8
require 'rspec'
require 'simplecov'
require 'simplecov-json'
require 'codeclimate-test-reporter'

SimpleCov.configure do
  root File.join(File.dirname(__FILE__), '..')
  project_name 'Ruby JWT - Ruby JSON Web Token implementation'
  SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter[
    SimpleCov::Formatter::HTMLFormatter,
    SimpleCov::Formatter::JSONFormatter
  ]

  add_filter 'spec'
end

SimpleCov.start if ENV['COVERAGE']
CodeClimate::TestReporter.start if ENV['CODECLIMATE_REPO_TOKEN']

require "#{File.dirname(__FILE__)}/../lib/jwt.rb"
