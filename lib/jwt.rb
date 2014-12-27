require 'openssl'
require 'base64'
require 'json'

module JWT
  class DecodeError < Exception;
  end
  class EncodeError < Exception;
  end

  def self.encode(payload, secret_or_key, algorithm = 'HS256', head = {})
    header = {
        'alg' => algorithm,
        'typ' => 'JWT'
    }

    token = []

    token << Base64.urlsafe_encode64(header.merge(head).to_json)
    token << Base64.urlsafe_encode64(payload.to_json)
    token << Base64.urlsafe_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), secret_or_key, token.join('.')))

    token.join '.'
  end

  def self.decode(token, secret_or_key = nil, verify = true, options = {}, &keyfinder)
    begin
      header, payload, signature = token.split('.')

      header    = JSON.parse(Base64.urlsafe_decode64(header))
      payload   = JSON.parse(Base64.urlsafe_decode64(payload))
      signature = Base64.urlsafe_decode64(signature)
    rescue Exception => e
      raise JWT::DecodeError.new e.message
    end

    valid = false

    if verify
      valid = signature === Base64.urlsafe_decode64(encode(payload, secret_or_key, header['alg'], header).split('.').last())
      raise JWT::DecodeError.new('Token verification failed. Data corrupted or pass phrase incorrect.') unless valid
    end

    [header, payload, signature, valid]
  end
end
