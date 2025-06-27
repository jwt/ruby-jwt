# frozen_string_literal: true

RSpec.describe JWT::JWA::Ecdsa do

  context "used across threads for encoding and decoding" do
    it "successfully encodes, decodes, and verifies" do
      threads = 10.times.map do
        Thread.new do
          public_key_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcKuFOqoNEN+TXylz4MVAWREa9yA8\npOF9QgGchnAy6Ad4P7yCpk+R3wCGTDLfNboYqUmbK5Hd9uHszf+EMTi22g==\n-----END PUBLIC KEY-----\n"
          private_key_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiF/iNuQem/yQyd16\nc9shf2Y9vMycOU7g6W6LTmkyj1ehRANCAARwq4U6qg0Q35NfKXPgxUBZERr3IDyk\n4X1CAZyGcDLoB3g/vIKmT5HfAIZMMt81uhipSZsrkd324ezN/4QxOLba\n-----END PRIVATE KEY-----\n"
          full_pem = private_key_pem + public_key_pem
          curve = OpenSSL::PKey.read(full_pem)
          public_key = OpenSSL::PKey::EC.new(public_key_pem)

          10.times do
            input_payload = {"aud" => "https://fcm.googleapis.com", "exp" => (Time.now.to_i + 600), "sub" => "mailto:example@example.com"}
            input_header = { "typ" => "JWT", "alg" => "ES256" }
            token = JWT.encode(input_payload, curve, 'ES256', input_header)

            output_payload, output_header = JWT.decode(token, public_key, true, { algorithm: 'ES256', verify_expiration: true })
            expect(output_payload).to eq input_payload
            expect(output_header).to eq input_header
          end
        end
      end

      threads.each(&:join)
    end
  end
end