require 'rubygems'
require 'rake'
require 'echoe'

Echoe.new('jwt', '2.0.0.pre') do |p|
  p.description              = 'JSON Web Token implementation in Ruby'
  p.url                      = 'http://github.com/progrium/ruby-jwt'
  p.author                   = 'Jeff Lindsay'
  p.email                    = 'progrium@gmail.com'
  p.ignore_pattern           = ['tmp/*']
  p.development_dependencies = ['echoe >=4.6.3']
  p.licenses                 = 'MIT'
end

task :test do
  sh 'bundle exec rspec'
end
