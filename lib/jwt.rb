# 
# JSON Web Token implementation
# 
# Minimum implementation based on this spec:
# http://self-issued.info/docs/draft-jones-json-web-token-01.html

require "base64"
require "openssl"
require "json"

module JWT
  class DecodeError < Exception; end
  
  def self.sign(algorithm, msg, key)
    raise NotImplementedError.new("Unsupported signing method") unless ["HS256", "HS384", "HS512"].include?(algorithm)
    OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new(algorithm.sub('HS', 'sha')), key, msg)
  end
  
  def self.base64url_decode(str)
    str += '=' * (4 - str.length.modulo(4))
    Base64.decode64(str.gsub("-", "+").gsub("_", "/"))
  end
  
  def self.base64url_encode(str)
    Base64.encode64(str).gsub("+", "-").gsub("/", "_").gsub("\n", "").gsub('=', '')
  end  
  
  def self.encode(payload, key, algorithm='HS256')
    segments = []
    header = {"typ" => "JWT", "alg" => algorithm}
    segments << base64url_encode(header.to_json)
    segments << base64url_encode(payload.to_json)
    signing_input = segments.join('.')
    signature = sign(algorithm, signing_input, key)
    segments << base64url_encode(signature)
    segments.join('.')
  end
  
  def self.decode(jwt, key=nil, verify=true)
    segments = jwt.split('.')
    raise JWT::DecodeError.new("Not enough or too many segments") unless segments.length == 3
    header_segment, payload_segment, crypto_segment = segments
    signing_input = [header_segment, payload_segment].join('.')
    begin
      header = JSON.parse(base64url_decode(header_segment))
      payload = JSON.parse(base64url_decode(payload_segment))
      signature = base64url_decode(crypto_segment)
    rescue JSON::ParserError
      raise JWT::DecodeError.new("Invalid segment encoding")
    end
    if verify
      begin
        if not signature == sign(header['alg'], signing_input, key)
          raise JWT::DecodeError.new("Signature verification failed")
        end
      rescue NotImplementedError
        raise JWT::DecodeError.new("Algorithm not supported")
      end
    end
    payload
  end

end
