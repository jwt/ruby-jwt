# frozen_string_literal: true

require 'securerandom'
require 'zlib'

# Inspired by
# https://github.com/jwt/ruby-jwt/issues/428

RSpec.describe 'SMART Health Cards decoder and verifier' do
  let(:jwk_keys) do
    JSON.parse('{ "keys": [{
      "kty": "EC",
      "kid": "3Kfdg-XwP-7gXyywtUfUADwBumDOPKMQx-iELL11W9s",
      "use": "sig",
      "alg": "ES256",
      "crv": "P-256",
      "x": "11XvRWy1I2S0EyJlyf_bWfw_TQ5CJJNLw78bHXNxcgw",
      "y": "eZXwxvO1hvCY0KucrPfKo7yAyMT6Ajc3N7OkAB6VYy8",
      "d": "FvOOk6hMixJ2o9zt4PCfan_UW7i4aOEnzj76ZaCI9Og" }]}')
  end

  let(:smart_health_card_token) do
    'eyJ6aXAiOiJERUYiLCJhbGciOiJFUzI1NiIsImtpZCI6IjNLZmRnLVh3UC03Z1h5eXd0VWZVQUR3QnVtRE9QS01ReC1pRUxMMTFXOXMifQ.3ZJJb9swEIX_SjC9ytoSR5VutQt0Q4sWTXMpfKCpscWCi8BFsBvov3dIO2haJDn1VN1GM_PxvUfegXAOOhi8H11XFG5EnjvFrB-QST_knNneFXhgapToCpoOaCEDvd1BV11ftldtednU-XL5MoOJQ3cH_jgidN9_M__GvTgVi1gQ6uk5oVTQ4ifzwuhnB7mZRF-1sMmAW-xRe8Hk17D9gdxHSbtB2Fu0LnI6uMrLvCJe_LsKupcYZyw6EyzHmyQfzo3sbAe4kZJoJyV0gD2SRyIHKb9ZSQP3-11JA_fFI-DPZIf2Y4ZM4QnClJDEg1eaZqxLZ-zFhDrm-N4MsV7lsJnJ4FaQ-dfMR1bVLqtFWS3qEuY5e1RN9byad39G7DzzwSW78cI9xguaGOdC49r0icBNL_Q-CXdH51Gd3w_dzCCb3Nh9EZMtnOgLPh0IwNMm1GUD82bOYDxHkOTs0KKO2h4mSEOG82BTK5q9EeqEqJPhMtqiqHbGKnqPUQvj3tiI7IUbJUtxrtYXb1CjZfLirXGj8ExSUBSiNP5TUNu4CmX6qicTrP_LBOv2XyfYxAaFCFb09PPjh-P6MDTjdfhCjV8.F248favB7uvtKSo9GbwIC-QtmpWeAsB-AtiFq2iACiDZQE0s38603dJp50vc1HEvZAB80RXecKQ1LYdkZbq8Rw'
  end

  subject(:smart_health_card_decoded) do
    test_class = self

    Class.new do
      include JWT

      algorithm 'ES256'

      jwk_resolver do |_options|
        test_class.jwk_keys
      end

      decode_payload do |raw_payload, headers|
        decoded_payload = ::Base64.urlsafe_decode64(raw_payload)

        raw_json = if headers['zip'] == 'DEF'
          begin
            Zlib::Inflate.inflate(decoded_payload)
          rescue Zlib::DataError
            zinflate = Zlib::Inflate.new(-::Zlib::MAX_WBITS)
            zinflate.inflate(decoded_payload)
          end
        else
          decoded_payload
        end

        ::JWT::JSON.parse(raw_json)
      end
    end
  end

  context 'when valid token is given' do
    it 'extracts the payload' do
      payload, header = smart_health_card_decoded.decode!(smart_health_card_token)
      expect(payload).to include('iss' => 'https://spec.smarthealth.cards/examples/issuer')
      expect(header).to eq(
        {'alg' => 'ES256',
       'kid' => '3Kfdg-XwP-7gXyywtUfUADwBumDOPKMQx-iELL11W9s',
       'zip' => 'DEF'}
      )
    end
  end
end
