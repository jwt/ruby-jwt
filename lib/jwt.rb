#
# JSON Web Token implementation
#
# Should be up to date with the latest spec:
# http://self-issued.info/docs/draft-jones-json-web-token-06.html

require 'base64'
require 'openssl'
require 'jwt/json'

module JWT
  class DecodeError < StandardError; end
  class VerificationError < DecodeError; end
  class ExpiredSignature < DecodeError; end
  class IncorrectAlgorithm < DecodeError; end
  class ImmatureSignature < DecodeError; end
  class InvalidIssuerError < DecodeError; end
  class InvalidIatError < DecodeError; end
  class InvalidAudError < DecodeError; end
  class InvalidSubError < DecodeError; end
  class InvalidJtiError < DecodeError; end
  extend JWT::Json

  NAMED_CURVES = {
    'prime256v1' => 'ES256',
    'secp384r1' => 'ES384',
    'secp521r1' => 'ES512',
  }

  module_function

  def sign(algorithm, msg, key)
    if ['HS256', 'HS384', 'HS512'].include?(algorithm)
      sign_hmac(algorithm, msg, key)
    elsif ['RS256', 'RS384', 'RS512'].include?(algorithm)
      sign_rsa(algorithm, msg, key)
    elsif ['ES256', 'ES384', 'ES512'].include?(algorithm)
      sign_ecdsa(algorithm, msg, key)
    else
      raise NotImplementedError.new('Unsupported signing method')
    end
  end

  def sign_rsa(algorithm, msg, private_key)
    private_key.sign(OpenSSL::Digest.new(algorithm.sub('RS', 'sha')), msg)
  end

  def sign_ecdsa(algorithm, msg, private_key)
    key_algorithm = NAMED_CURVES[private_key.group.curve_name]
    if algorithm != key_algorithm
      raise IncorrectAlgorithm.new("payload algorithm is #{algorithm} but #{key_algorithm} signing key was provided")
    end

    digest = OpenSSL::Digest.new(algorithm.sub('ES', 'sha'))
    private_key.dsa_sign_asn1(digest.digest(msg))
  end

  def verify_rsa(algorithm, public_key, signing_input, signature)
    public_key.verify(OpenSSL::Digest.new(algorithm.sub('RS', 'sha')), signature, signing_input)
  end

  def verify_ecdsa(algorithm, public_key, signing_input, signature)
    key_algorithm = NAMED_CURVES[public_key.group.curve_name]
    if algorithm != key_algorithm
      raise IncorrectAlgorithm.new("payload algorithm is #{algorithm} but #{key_algorithm} verification key was provided")
    end

    digest = OpenSSL::Digest.new(algorithm.sub('ES', 'sha'))
    public_key.dsa_verify_asn1(digest.digest(signing_input), signature)
  end

  def sign_hmac(algorithm, msg, key)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new(algorithm.sub('HS', 'sha')), key, msg)
  end

  def base64url_decode(str)
    str += '=' * (4 - str.length.modulo(4))
    Base64.decode64(str.tr('-_', '+/'))
  end

  def base64url_encode(str)
    Base64.encode64(str).tr('+/', '-_').gsub(/[\n=]/, '')
  end

  def encoded_header(algorithm='HS256', header_fields={})
    header = {'typ' => 'JWT', 'alg' => algorithm}.merge(header_fields)
    base64url_encode(encode_json(header))
  end

  def encoded_payload(payload)
    base64url_encode(encode_json(payload))
  end

  def encoded_signature(signing_input, key, algorithm)
    if algorithm == 'none'
      ''
    else
      signature = sign(algorithm, signing_input, key)
      base64url_encode(signature)
    end
  end

  def encode(payload, key, algorithm='HS256', header_fields={})
    algorithm ||= 'none'
    segments = []
    segments << encoded_header(algorithm, header_fields)
    segments << encoded_payload(payload)
    segments << encoded_signature(segments.join('.'), key, algorithm)
    segments.join('.')
  end

  def raw_segments(jwt, verify=true)
    segments = jwt.split('.')
    required_num_segments = verify ? [3] : [2,3]
    raise JWT::DecodeError.new('Not enough or too many segments') unless required_num_segments.include? segments.length
    segments
  end

  def decode_header_and_payload(header_segment, payload_segment)
    header = decode_json(base64url_decode(header_segment))
    payload = decode_json(base64url_decode(payload_segment))
    [header, payload]
  end

  def decoded_segments(jwt, verify=true)
    header_segment, payload_segment, crypto_segment = raw_segments(jwt, verify)
    header, payload = decode_header_and_payload(header_segment, payload_segment)
    signature = base64url_decode(crypto_segment.to_s) if verify
    signing_input = [header_segment, payload_segment].join('.')
    [header, payload, signature, signing_input]
  end

  def decode(jwt, key=nil, verify=true, options={}, &keyfinder)
    raise JWT::DecodeError.new('Nil JSON web token') unless jwt

    header, payload, signature, signing_input = decoded_segments(jwt, verify)
    raise JWT::DecodeError.new('Not enough or too many segments') unless header && payload

    default_options = {
      :verify_expiration => true,
      :verify_not_before => true,
      :verify_iss => false,
      :verify_iat => false,
      :verify_jti => false,
      :verify_aud => false,
      :verify_sub => false,
      :leeway => 0
    }

    options = default_options.merge(options)

    if verify
      algo, key = signature_algorithm_and_key(header, key, &keyfinder)
      if options[:algorithm] && algo != options[:algorithm]
        raise JWT::IncorrectAlgorithm.new('Expected a different algorithm')
      end
      verify_signature(algo, key, signing_input, signature)
    end

    if options[:verify_expiration] && payload.include?('exp')
      raise JWT::ExpiredSignature.new('Signature has expired') unless payload['exp'].to_i > (Time.now.to_i - options[:leeway])
    end
    if options[:verify_not_before] && payload.include?('nbf')
      raise JWT::ImmatureSignature.new('Signature nbf has not been reached') unless payload['nbf'].to_i < (Time.now.to_i + options[:leeway])
    end
    if options[:verify_iss] && payload.include?('iss')
      raise JWT::InvalidIssuerError.new("Invalid issuer. Expected #{options['iss']}, received #{payload['iss']}") unless payload['iss'].to_s == options['iss'].to_s
    end
    if options[:verify_iat] && payload.include?('iat')
      raise JWT::InvalidIatError.new('Invalid iat') unless (payload['iat'].is_a?(Integer) and payload['iat'].to_i <= Time.now.to_i)
    end
    if options[:verify_aud] && payload.include?('aud')
      if payload['aud'].is_a?(Array)
        raise JWT::InvalidAudError.new('Invalid audience') unless payload['aud'].include?(options['aud'])
      else
        raise JWT::InvalidAudError.new("Invalid audience. Expected #{options['aud']}, received #{payload['aud']}") unless payload['aud'].to_s == options['aud'].to_s
      end
    end
    if options[:verify_sub] && payload.include?('sub')
      raise JWT::InvalidSubError.new("Invalid subject. Expected #{options['sub']}, received #{payload['sub']}") unless payload['sub'].to_s == options['sub'].to_s
    end
    if options[:verify_jti] && payload.include?('jti')
      raise JWT::InvalidJtiError.new('need iat for verify jwt id') unless payload.include?('iat')
      raise JWT::InvalidJtiError.new('Not a uniq jwt id') unless options['jti'].to_s == Digest::MD5.hexdigest("#{key}:#{payload['iat']}")
    end

    return payload,header
  end

  def signature_algorithm_and_key(header, key, &keyfinder)
    if keyfinder
      key = keyfinder.call(header)
    end
    [header['alg'], key]
  end

  def verify_signature(algo, key, signing_input, signature)
    begin
      if ['HS256', 'HS384', 'HS512'].include?(algo)
        raise JWT::VerificationError.new('Signature verification failed') unless secure_compare(signature, sign_hmac(algo, signing_input, key))
      elsif ['RS256', 'RS384', 'RS512'].include?(algo)
        raise JWT::VerificationError.new('Signature verification failed') unless verify_rsa(algo, key, signing_input, signature)
      elsif ['ES256', 'ES384', 'ES512'].include?(algo)
        raise JWT::VerificationError.new('Signature verification failed') unless verify_ecdsa(algo, key, signing_input, signature)
      else
        raise JWT::VerificationError.new('Algorithm not supported')
      end
    rescue OpenSSL::PKey::PKeyError
      raise JWT::VerificationError.new('Signature verification failed')
    ensure
      OpenSSL.errors.clear
    end
  end

  # From devise
  # constant-time comparison algorithm to prevent timing attacks
  def secure_compare(a, b)
    return false if a.nil? || b.nil? || a.empty? || b.empty? || a.bytesize != b.bytesize
    l = a.unpack "C#{a.bytesize}"

    res = 0
    b.each_byte { |byte| res |= byte ^ l.shift }
    res == 0
  end

end
