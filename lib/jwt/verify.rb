module JWT
  module Verify
    def self.verify_expiration payload, options
      return if !payload.include?('exp')

      if payload['exp'].to_i < (Time.now.to_i - options[:leeway])
        fail(JWT::ExpiredSignature, 'Signature has expired')
      end
    end

    def self.verify_not_before payload, options
      return if !payload.include?('nbf')

      if payload['nbf'].to_i > (Time.now.to_i + options[:leeway])
        fail(JWT::ImmatureSignature, 'Signature nbf has not been reached')
      end
    end

    def self.verify_iss payload, options
      return if !options[:iss]

      if payload['iss'].to_s != options[:iss].to_s
        fail(
          JWT::InvalidIssuerError,
          "Invalid issuer. Expected #{options[:iss]}, received #{payload['iss'] || '<none>'}"
        )
      end
    end

    def self.verify_iat payload, options
      return if !payload.include?('iat')

      if !(payload['iat'].is_a?(Integer)) || payload['iat'].to_i > (Time.now.to_i + options[:leeway])
        fail(JWT::InvalidIatError, 'Invalid iat')
      end
    end

    def self.verify_jti payload, options
      fail(JWT::InvalidJtiError, 'Missing jti') if payload['jti'].to_s == ''
    end

    def self.verify_aud payload, options
      return if !options[:aud]

      if payload[:aud].is_a?(Array)
        if !payload['aud'].include?(options[:aud].to_s)
          fail(
            JWT::InvalidAudError,
            'Invalid audience'
          )
        end
      else
        if payload['aud'].to_s != options[:aud].to_s
          fail(JWT::InvalidAudError, "Invalid audience. Expected #{options[:aud]}, received #{payload['aud'] || '<none>'}")
        end
      end
    end

    def self.verify_sub payload, options
      return if !options[:sub]

      if payload['sub'].to_s != options[:sub].to_s
        fail(
          JWT::InvalidSubError,
          "Invalid subject. Expected #{options[:sub]}, received #{payload['sub'] || '<none>'}"
        )
      end
    end
  end
end
