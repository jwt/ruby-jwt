# frozen_string_literal: true

appraise 'standalone' do
  remove_gem 'rubocop'
end

appraise 'openssl' do
  gem 'openssl', '~> 2.1'
  remove_gem 'rubocop'
end

appraise 'rbnacl' do
  gem 'rbnacl', '>= 6'
  remove_gem 'rubocop'
end

appraise 'rbnacl_pre_6' do
  gem 'rbnacl', '< 6'
  remove_gem 'rubocop'
end
