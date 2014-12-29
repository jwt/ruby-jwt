require 'base64'

module JWT
  module Base64
    extend self

    def encode(data)
      ::Base64.encode64(data).tr('+/', '-_').gsub /[\n=]/, ''
    end

    def decode(data)
      data += '=' * (4 - data.length.modulo(4))

      ::Base64.decode64(data.tr('-_', '+/'))
    end
  end
end
