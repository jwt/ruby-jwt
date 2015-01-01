require 'openssl'
require 'json'
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

    header  = Base64.encode header.merge(head).to_json
    payload = Base64.encode payload.to_json

    token = [header, payload]

    token << JWA.sign(algorithm, (header + '.' + payload).to_s, secret_or_key)

    token.join '.'
  end

  def decode(token, secret_or_key = nil, verify = true)
    orig_header, orig_payload, orig_signature = token.split('.')

    header    = JSON.parse(Base64.decode(orig_header))
    payload   = JSON.parse(Base64.decode(orig_payload))
    signature = header['alg'] == 'none' ? '' : Base64.decode(orig_signature)
    
    valid = false

    if verify
      valid = verify(header['alg'], (orig_header + '.' + orig_payload), orig_signature, secret_or_key)
      raise JWT::DecodeError.new('Token verification failed. Data corrupted or pass phrase incorrect.') unless valid
    end

    [header, payload, signature, valid]
  end

  def verify(algorithm, payload, signature, secret_or_key)
    JWA.verify(algorithm, payload, signature, secret_or_key)
  end

  private :verify
end
