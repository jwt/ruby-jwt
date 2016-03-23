require 'jwt/error'

module JWT
  # JWT verify methods
  class Verify
    class << self
      %w[verify_aud verify_expiration verify_iat verify_iss verify_jti verify_not_before verify_sub].each do |method_name|
        define_method method_name do |payload, options|
          new(payload, options).send(method_name)
        end
      end
    end

    def initialize(payload, options)
      @payload = payload
      @options = options
    end

    def verify_aud
      return unless (options_aud = extract_option(:aud))

      if @payload['aud'].is_a?(Array)
        fail(
          JWT::InvalidAudError,
          'Invalid audience'
        ) unless @payload['aud'].include?(options_aud.to_s)
      else
        fail(
          JWT::InvalidAudError,
          "Invalid audience. Expected #{options_aud}, received #{@payload['aud'] || '<none>'}"
        ) unless @payload['aud'].to_s == options_aud.to_s
      end
    end

    def verify_expiration
      return unless @payload.include?('exp')

      if @payload['exp'].to_i < (Time.now.to_i - leeway)
        fail(JWT::ExpiredSignature, 'Signature has expired')
      end
    end

    def verify_iat
      return unless @payload.include?('iat')

      if !(@payload['iat'].is_a?(Numeric)) || @payload['iat'].to_f > (Time.now.to_f + leeway)
        fail(JWT::InvalidIatError, 'Invalid iat')
      end
    end

    def verify_iss
      return unless (options_iss = extract_option(:iss))

      if @payload['iss'].to_s != options_iss.to_s
        fail(
          JWT::InvalidIssuerError,
          "Invalid issuer. Expected #{options_iss}, received #{@payload['iss'] || '<none>'}"
        )
      end
    end

    def verify_jti
      options_verify_jti = extract_option(:verify_jti)
      if options_verify_jti.respond_to?(:call)
        fail(JWT::InvalidJtiError, 'Invalid jti') unless options_verify_jti.call(@payload['jti'])
      else
        fail(JWT::InvalidJtiError, 'Missing jti') if @payload['jti'].to_s.strip.empty?
      end
    end

    def verify_not_before
      return unless @payload.include?('nbf')

      if @payload['nbf'].to_i > (Time.now.to_i + leeway)
        fail(JWT::ImmatureSignature, 'Signature nbf has not been reached')
      end
    end

    def verify_sub
      return unless (options_sub = extract_option(:sub))

      fail(
        JWT::InvalidSubError,
        "Invalid subject. Expected #{options_sub}, received #{@payload['sub'] || '<none>'}"
      ) unless @payload['sub'].to_s == options_sub.to_s
    end

    private

    def extract_option(key)
      @options.values_at(key.to_sym, key.to_s).compact.first
    end

    def leeway
      extract_option :leeway
    end
  end
end
