require 'codeclimate-test-reporter'
CodeClimate::TestReporter.start

SimpleCov.configure do
  root File.join(File.dirname(__FILE__), '..')
  project_name 'Ruby JWT - Ruby JSON Web Token implementation'
  SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter[
    CodeClimate::TestReporter::Formatter,
    SimpleCov::Formatter::HTMLFormatter
  ]

  add_filter 'spec'
end

SimpleCov.start if ENV['COVERAGE']

CERT_PATH = File.join(File.dirname(__FILE__), '..', 'tmp', 'certs')

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = [:should, :expect]
  end

  config.run_all_when_everything_filtered = true
  config.filter_run :focus

  config.order = 'random'
end
