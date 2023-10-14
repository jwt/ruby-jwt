#!/usr/bin/env ruby
# frozen_string_literal: true

require 'jwt'

puts "Running simple encode/decode test for #{JWT.gem_version}"
secret = 'secretkeyforsigning'
token  = JWT.encode({ con: 'tent' }, secret, 'HS256')
JWT.decode(token, secret, true, algorithm: 'HS256')
