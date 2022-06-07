# frozen_string_literal: true

# Moments version builder module
module JWT
  def self.gem_version
    Gem::Version.new VERSION::STRING
  end

  # Moments version builder module
  module VERSION
    # major version
    MAJOR = 2
    # minor version
    MINOR = 4
    # tiny version
    TINY  = 1
    # alpha, beta, etc. tag
    PRE   = nil

    # Build version string
    STRING = [MAJOR, MINOR, TINY, PRE].compact.join('.')
  end
end
