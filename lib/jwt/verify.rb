require 'jwt/error'

module JWT
  # JWT verify methods
  class Verify
    class << self
      %i[verify_aud verify_expiration verify_iat verify_iss verify_jti verify_not_before verify_sub].each do |method_name|
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
      return unless @options[:aud]

      if @payload['aud'].is_a?(Array)
        fail(
          JWT::InvalidAudError,
          'Invalid audience'
        ) unless @payload['aud'].include?(@options[:aud].to_s)
      else
        fail(
          JWT::InvalidAudError,
          "Invalid audience. Expected #{@options[:aud]}, received #{@payload['aud'] || '<none>'}"
        ) unless @payload['aud'].to_s == @options[:aud].to_s
      end
    end

    def verify_expiration
      return unless @payload.include?('exp')

      if @payload['exp'].to_i < (Time.now.to_i - @options[:leeway])
        fail(JWT::ExpiredSignature, 'Signature has expired')
      end
    end

    def verify_iat
      return unless @payload.include?('iat')

      if !(@payload['iat'].is_a?(Integer)) || @payload['iat'].to_i > (Time.now.to_i + @options[:leeway])
        fail(JWT::InvalidIatError, 'Invalid iat')
      end
    end

    def verify_iss
      return unless @options[:iss]

      if @payload['iss'].to_s != @options[:iss].to_s
        fail(
          JWT::InvalidIssuerError,
          "Invalid issuer. Expected #{@options[:iss]}, received #{@payload['iss'] || '<none>'}"
        )
      end
    end

    def verify_jti
      if @options[:verify_jti].class == Proc
        fail(JWT::InvalidJtiError, 'Invalid jti') unless @options[:verify_jti].call(@payload['jti'])
      else
        fail(JWT::InvalidJtiError, 'Missing jti') if @payload['jti'].to_s == ''
      end
    end

    def verify_not_before
      return unless @payload.include?('nbf')

      if @payload['nbf'].to_i > (Time.now.to_i + @options[:leeway])
        fail(JWT::ImmatureSignature, 'Signature nbf has not been reached')
      end
    end

    def verify_sub
      return unless @options[:sub]

      fail(
        JWT::InvalidSubError,
        "Invalid subject. Expected #{@options[:sub]}, received #{@payload['sub'] || '<none>'}"
      ) unless @payload['sub'].to_s == @options[:sub].to_s
    end
  end
end
