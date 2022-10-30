# frozen_string_literal: true

require 'bundler/setup'
require 'bundler/gem_tasks'

require 'rspec/core/rake_task'
require 'rubocop/rake_task'

RSpec::Core::RakeTask.new(:test)
RuboCop::RakeTask.new(:rubocop)

task default: %i[rubocop test]
