# frozen_string_literal: true

module JWT
  module DefaultOptions
    LEEWAY_DEFAULT = 0
    ALGORITHMS_DEFAULT = ['HS256'].freeze

    VERIFY_CLAIMS_DEFAULTS = {
      leeway: LEEWAY_DEFAULT,
      verify_expiration: true,
      verify_not_before: true,
      verify_iss: false,
      verify_iat: false,
      verify_jti: false,
      verify_aud: false,
      verify_sub: false,
      required_claims: []
    }.freeze

    DECODE_DEFAULT_OPTIONS = {
      verify: true,
      algorithms: ALGORITHMS_DEFAULT
    }.merge(VERIFY_CLAIMS_DEFAULTS).freeze
  end
end
