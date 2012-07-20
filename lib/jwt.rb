#
# JSON Web Token implementation
#
# Should be up to date with the latest spec:
# http://self-issued.info/docs/draft-jones-json-web-token-06.html

require "base64"
require "openssl"
require "multi_json"

module JWT
  class DecodeError < Exception; end

  def self.sign(algorithm, msg, key)
    if ["HS256", "HS384", "HS512"].include?(algorithm)
      sign_hmac(algorithm, msg, key)
    elsif ["RS256", "RS384", "RS512"].include?(algorithm)
      sign_rsa(algorithm, msg, key)
    else
      raise NotImplementedError.new("Unsupported signing method")
    end
  end

  def self.sign_rsa(algorithm, msg, private_key)
    private_key.sign(OpenSSL::Digest::Digest.new(algorithm.sub('RS', 'sha')), msg)
  end

  def self.verify_rsa(algorithm, public_key, signing_input, signature)
    public_key.verify(OpenSSL::Digest::Digest.new(algorithm.sub('RS', 'sha')), signature, signing_input)
  end

  def self.sign_hmac(algorithm, msg, key)
    OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new(algorithm.sub('HS', 'sha')), key, msg)
  end

  def self.base64url_decode(str)
    str += '=' * (4 - str.length.modulo(4))
    Base64.decode64(str.gsub("-", "+").gsub("_", "/"))
  end

  def self.base64url_encode(str)
    Base64.encode64(str).gsub("+", "-").gsub("/", "_").gsub("\n", "").gsub('=', '')
  end

  def self.encode(payload, key, algorithm='HS256', header_fields={})
    algorithm ||= "none"
    segments = []
    header = {"typ" => "JWT", "alg" => algorithm}.merge(header_fields)
    segments << base64url_encode(MultiJson.encode(header))
    segments << base64url_encode(MultiJson.encode(payload))
    signing_input = segments.join('.')
    if algorithm != "none"
      signature = sign(algorithm, signing_input, key)
      segments << base64url_encode(signature)
    else
      segments << ""
    end
    segments.join('.')
  end

  def self.decode(jwt, key=nil, verify=true, &keyfinder)
    segments = jwt.split('.')
    raise JWT::DecodeError.new("Not enough or too many segments") unless [2,3].include? segments.length
    header_segment, payload_segment, crypto_segment = segments
    signing_input = [header_segment, payload_segment].join('.')
    begin
      header = MultiJson.decode(base64url_decode(header_segment))
      payload = MultiJson.decode(base64url_decode(payload_segment))
      signature = base64url_decode(crypto_segment) if verify
    rescue JSON::ParserError
      raise JWT::DecodeError.new("Invalid segment encoding")
    end
    if verify == true
      algo = header['alg']

      if keyfinder
        key = keyfinder.call(header)
      end

      begin
        if ["HS256", "HS384", "HS512"].include?(algo)
          raise JWT::DecodeError.new("Signature verification failed") unless signature == sign_hmac(algo, signing_input, key)
        elsif ["RS256", "RS384", "RS512"].include?(algo)
          raise JWT::DecodeError.new("Signature verification failed") unless verify_rsa(algo, key, signing_input, signature)
        else
          raise JWT::DecodeError.new("Algorithm not supported")
        end
      rescue OpenSSL::PKey::PKeyError
        raise JWT::DecodeError.new("Signature verification failed")
      end
    end
    payload
  end

end
