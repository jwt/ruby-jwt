require 'bundler/gem_tasks'

begin
  require 'rspec/core/rake_task'

  RSpec::Core::RakeTask.new(:test)

  task default: :test
rescue LoadError
  puts 'RSpec rake tasks not available. Can not set up test execution via Rake'
end
