require 'rubygems'
require 'rake'
require 'echoe'

Echoe.new('jwt', '0.1.11') do |p|
  p.description    = "JSON Web Token implementation in Ruby"
  p.url            = "http://github.com/progrium/ruby-jwt"
  p.author         = "Jeff Lindsay"
  p.email          = "progrium@gmail.com"
  p.ignore_pattern = ["tmp/*"]
  p.runtime_dependencies = ["multi_json >=1.5"]
  p.development_dependencies = ["echoe >=4.6.3"]
  p.licenses       = "MIT"
end

task :test do
  sh "rspec spec/jwt_spec.rb"
end
