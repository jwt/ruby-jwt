# encoding: utf-8

# Moments version builder module
module JWT
  def self.gem_version
    Gem::Version.new VERSION::STRING
  end

  # Moments version builder module
  module VERSION
    # major version
    MAJOR = 1
    # minor version
    MINOR = 5
    # tiny version
    TINY  = 4
    # alpha, beta, etc. tag
    PRE   = nil

    # Build version string
    STRING = [MAJOR, MINOR, TINY, PRE].compact.join('.')
  end
end
