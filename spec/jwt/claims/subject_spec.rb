# frozen_string_literal: true

RSpec.describe JWT::Claims::Subject do
  let(:subject_claim) { 'ruby-jwt-subject' }
  let(:payload) { { 'sub' => subject_claim } }
  let(:expected_subject) { 'ruby-jwt-subject' }

  subject(:verify!) { described_class.new(expected_subject: expected_subject).verify!(context: SpecSupport::Token.new(payload: payload)) }

  context 'when the subject matches the expected subject' do
    it 'passes validation' do
      verify!
    end
  end

  context 'when the subject does not match the expected subject' do
    let(:subject_claim) { 'another-subject' }
    it 'raises JWT::InvalidSubError' do
      expect { verify! }.to raise_error(JWT::InvalidSubError, 'Invalid subject. Expected ruby-jwt-subject, received another-subject')
    end
  end

  context 'when the subject is a number that matches the expected subject' do
    let(:subject_claim) { 123 }
    let(:expected_subject) { '123' }
    it 'passes validation' do
      verify!
    end
  end

  context 'when payload does not contain a subject' do
    let(:payload) { {} }
    it 'raises JWT::InvalidSubError' do
      expect { verify! }.to raise_error(JWT::InvalidSubError, 'Invalid subject. Expected ruby-jwt-subject, received <none>')
    end
  end

  context 'when payload is not a Hash' do
    [['x'], 42, nil, 'sub'].each do |non_hash_payload|
      context "when payload is #{non_hash_payload.inspect}" do
        let(:payload) { non_hash_payload }
        let(:expected_subject) { 'sub' }
        it 'raises JWT::InvalidSubError' do
          expect { verify! }.to raise_error(JWT::InvalidSubError, 'Invalid subject. Expected sub, received <none>')
        end
      end
    end
  end

  [nil, ''].each do |blank_subject|
    context "when the expected subject is #{blank_subject.inspect}" do
      let(:expected_subject) { blank_subject }

      context 'when payload does not contain a subject' do
        let(:payload) { {} }
        it 'raises JWT::InvalidSubError' do
          expect { verify! }.to raise_error(JWT::InvalidSubError, 'Invalid subject. Expected , received <none>')
        end
      end

      context 'when the subject is an empty String' do
        let(:subject_claim) { '' }
        it 'raises JWT::InvalidSubError' do
          expect { verify! }.to raise_error(JWT::InvalidSubError, 'Invalid subject. Expected , received ')
        end
      end
    end
  end
end
