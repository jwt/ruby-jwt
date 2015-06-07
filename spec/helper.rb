# encoding: utf-8
require 'rspec'
require 'simplecov'
require 'simplecov-json'

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

require "#{File.dirname(__FILE__)}/../lib/jwt.rb"
