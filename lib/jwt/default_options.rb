module JWT
  module DefaultOptions
    NAMED_CURVES = { 'prime256v1' => 'ES256', 'secp384r1' => 'ES384', 'secp521r1' => 'ES512' }.freeze

    DEFAULT_OPTIONS = {
      verify_expiration: true,
      verify_not_before: true,
      verify_iss: false,
      verify_iat: false,
      verify_jti: false,
      verify_aud: false,
      verify_sub: false,
      leeway: 0
    }.freeze
  end
end
