# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{jwt}
  s.version = "0.1.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.2") if s.respond_to? :required_rubygems_version=
  s.authors = [%q{Jeff Lindsay}]
  s.cert_chain = [%q{/Users/progrium/.gem/gem-public_cert.pem}]
  s.date = %q{2011-06-30}
  s.description = %q{JSON Web Token implementation in Ruby}
  s.email = %q{jeff.lindsay@twilio.com}
  s.extra_rdoc_files = [%q{lib/jwt.rb}]
  s.files = [%q{Rakefile}, %q{lib/jwt.rb}, %q{spec/jwt.rb}, %q{Manifest}, %q{jwt.gemspec}]
  s.homepage = %q{http://github.com/progrium/ruby-jwt}
  s.rdoc_options = [%q{--line-numbers}, %q{--inline-source}, %q{--title}, %q{Jwt}, %q{--main}, %q{README.md}]
  s.require_paths = [%q{lib}]
  s.rubyforge_project = %q{jwt}
  s.rubygems_version = %q{1.8.5}
  s.signing_key = %q{/Users/progrium/.gem/gem-private_key.pem}
  s.summary = %q{JSON Web Token implementation in Ruby}

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<json>, [">= 1.2.4"])
    else
      s.add_dependency(%q<json>, [">= 1.2.4"])
    end
  else
    s.add_dependency(%q<json>, [">= 1.2.4"])
  end
end
