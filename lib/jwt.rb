require 'openssl'
require 'json'
require 'base64'
require 'jwt/base64'
require 'jwa'

module JWT
  extend self

  class DecodeError < Exception;
  end
  class EncodeError < Exception;
  end

  def encode(payload, secret_or_key, algorithm = 'HS256', head = {})
    header = {
        'alg' => algorithm,
        'typ' => 'JWT'
    }

    token = []

    token << Base64.encode(header.merge(head).to_json)
    token << Base64.encode(payload.to_json)

    signature = if algorithm != 'none'
                  Base64.encode(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), secret_or_key, token.join('.')))
                else
                  ''
                end

    token << signature

    token.join '.'
  end

  def decode(token, secret_or_key = nil, verify = true)
    begin
      header, payload, signature = token.split('.')

      header    = JSON.parse(Base64.decode(header))
      payload   = JSON.parse(Base64.decode(payload))
      signature = if header['alg'] == 'none'
                    ''
                  else
                    Base64.decode(signature)
                  end
    rescue Exception => e
      raise JWT::DecodeError.new e.message
    end

    valid = false

    if verify && header['alg'] != 'none'
      valid = signature === Base64.decode(encode(payload, secret_or_key, header['alg'], header).split('.').last())
      raise JWT::DecodeError.new('Token verification failed. Data corrupted or pass phrase incorrect.') unless valid
    end

    [header, payload, signature, valid]
  end
end
