require "codeclimate-test-reporter"
CodeClimate::TestReporter.start

CERT_PATH = File.join(File.dirname(__FILE__), '..', 'tmp', 'certs')

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = [:should, :expect]
  end

  config.run_all_when_everything_filtered = true
  config.filter_run :focus

  config.order = 'random'
end
