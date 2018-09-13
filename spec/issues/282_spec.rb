require 'spec_helper'

describe "Issue 282" do
    it "exp claim should be treated the same" do
        payload = {exp: Time.now}
        expect {JWT.encode payload, 'secret'}.to raise_error JWT::InvalidPayload

        payload = {'exp' => Time.now}
        expect {JWT.encode payload, 'secret'}.to raise_error JWT::InvalidPayload
    end
end
