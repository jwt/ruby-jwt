# frozen_string_literal: true

RSpec.describe JWT::X5tKeyFinder do
  let(:root_key) { test_pkey('rsa-2048-private.pem') }
  let(:root_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake-ca/CN=Fake CA') }
  let(:root_certificate) { generate_root_cert(root_dn, root_key) }
  let(:leaf_key) { generate_key }
  let(:leaf_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake/CN=Fake') }
  let(:leaf_certificate) do
    cert = generate_cert(leaf_dn, leaf_key.public_key, 2)
    cert.sign(root_key, 'sha256')
    cert
  end

  subject(:keyfinder) { described_class.new([leaf_certificate]).from(header) }

  context 'when certificates argument is nil' do
    subject(:keyfinder) { described_class.new(nil).from({}) }

    it 'raises an argument error' do
      expect { keyfinder }.to raise_error(ArgumentError, 'Certificates must be specified')
    end
  end

  context 'when certificates argument is not array' do
    subject(:keyfinder) { described_class.new('certificate').from({}) }

    it 'raises an argument error' do
      expect { keyfinder }.to raise_error(ArgumentError, 'Certificates must be specified')
    end
  end

  context 'when x5t header is not present' do
    subject(:keyfinder) { described_class.new([leaf_certificate]).from({}) }

    it 'raises a decode error' do
      expect { keyfinder }.to raise_error(JWT::DecodeError, 'x5t or x5t#S256 header parameter is required')
    end
  end

  context 'when the x5t header is present' do
    let(:x5t) { Base64.urlsafe_encode64(OpenSSL::Digest::SHA1.new(leaf_certificate.to_der).digest) }
    let(:header) { { 'x5t' => x5t } }

    it 'returns the public key from a certificate matching the x5t thumbprint' do
      expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
      expect(keyfinder.public_key.to_der).to eq(leaf_certificate.public_key.to_der)
    end

    context '::JWT.decode' do
      let(:token_payload) { { 'data' => 'something' } }
      let(:encoded_token) { JWT.encode(token_payload, leaf_key, 'RS256', { 'x5t' => x5t }) }
      let(:decoded_payload) do
        JWT.decode(encoded_token, nil, true, algorithms: ['RS256'], x5t: { certificates: [leaf_certificate] }).first
      end

      it 'returns the encoded payload after successful certificate thumbprint verification' do
        expect(decoded_payload).to eq(token_payload)
      end
    end

    context 'when no certificate matches the thumbprint' do
      let(:different_cert) do
        generate_cert(leaf_dn, generate_key.public_key, 3).tap do |cert|
          cert.sign(root_key, 'sha256')
        end
      end
      subject(:keyfinder) { described_class.new([different_cert]).from(header) }

      it 'raises a verification error' do
        expect { keyfinder }.to raise_error(JWT::VerificationError, 'No certificate matches the x5t thumbprint')
      end
    end
  end

  context 'when the x5t#S256 header is present' do
    let(:x5t) { Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.new(leaf_certificate.to_der).digest) }
    let(:header) { { 'x5t#S256' => x5t } }

    it 'returns the public key from a certificate matching the x5t thumbprint' do
      expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
      expect(keyfinder.public_key.to_der).to eq(leaf_certificate.public_key.to_der)
    end

    context '::JWT.decode' do
      let(:token_payload) { { 'data' => 'something' } }
      let(:encoded_token) { JWT.encode(token_payload, leaf_key, 'RS256', { 'x5t#S256' => x5t }) }
      let(:decoded_payload) do
        JWT.decode(encoded_token, nil, true, algorithms: ['RS256'], x5t: { certificates: [leaf_certificate] }).first
      end

      it 'returns the encoded payload after successful certificate thumbprint verification' do
        expect(decoded_payload).to eq(token_payload)
      end
    end

    context 'when no certificate matches the thumbprint' do
      let(:different_cert) do
        generate_cert(leaf_dn, generate_key.public_key, 3).tap do |cert|
          cert.sign(root_key, 'sha256')
        end
      end
      subject(:keyfinder) { described_class.new([different_cert]).from(header) }

      it 'raises a verification error' do
        expect { keyfinder }.to raise_error(JWT::VerificationError, 'No certificate matches the x5t thumbprint')
      end
    end
  end

  private

  def generate_key
    OpenSSL::PKey::RSA.new(2048)
  end

  def generate_root_cert(root_dn, root_key)
    generate_cert(root_dn, root_key, 1).tap do |cert|
      ef = OpenSSL::X509::ExtensionFactory.new
      cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
      cert.sign(root_key, 'sha256')
    end
  end

  def generate_cert(subject, key, serial, issuer: nil, not_after: nil)
    OpenSSL::X509::Certificate.new.tap do |cert|
      issuer ||= cert
      cert.version = 2
      cert.serial = serial
      cert.subject = subject
      cert.issuer = issuer.subject
      cert.public_key = key
      now = Time.now
      cert.not_before = now - 3600
      cert.not_after = not_after || (now + 3600)
    end
  end
end
