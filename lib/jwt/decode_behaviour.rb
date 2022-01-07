# frozen_string_literal: true

require 'jwt/signature'
require 'jwt/verify'
require 'jwt/x5c_key_finder'

module JWT
  module DecodeBehaviour
    def verify_claims!(claim_options)
      Verify.verify_claims(payload, claim_options)
      Verify.verify_required_claims(payload, claim_options)
    end
  end
end
