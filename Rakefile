require 'rubygems'
require 'rake'
require 'echoe'

Echoe.new('jwt', '0.1.4') do |p|
  p.description    = "JSON Web Token implementation in Ruby"
  p.url            = "http://github.com/progrium/ruby-jwt"
  p.author         = "Jeff Lindsay"
  p.email          = "jeff.lindsay@twilio.com"
  p.ignore_pattern = ["tmp/*"]
  p.runtime_dependencies = ["json >=1.2.4"]
  p.development_dependencies = []
end

task :test do
  sh "rspec spec/jwt.rb"
end
