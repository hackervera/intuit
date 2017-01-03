require "./spec_helper"

# describe Intuit::Session do
#   describe

describe Intuit::Account do
  describe "#create" do
    it "should update pointer with random bytes" do
      account = Intuit::Account.new
      account.create
      account.ptr.class.should eq Pointer(UInt8)
      account.random.as(Slice(UInt8)).bytesize.should eq account.random_length
      # puts account.ptr.to_slice(account.random_length.as(UInt64))
    end
  end
  describe "#identity_keys" do
    it "should create identity keys for account" do
      account = Intuit::Account.new
      account.create
      account.identity_keys.bytesize.should eq account.identity_length
    end
  end
  describe "#to_json" do
    it "should return a json object to upload to matrix for key storage" do
      account = Intuit::Account.new(device_id: "GDKOVUODQU")
      account.create
      account.generate_one_time_keys(5)
      puts account.to_json
    end
  end
  describe "#generate_one_time_keys" do
    it "should generate one time use keys" do
      account = Intuit::Account.new(device_id: "GDKOVUODQU")
      account.create
      account.generate_one_time_keys(5)
      # pp JSON.parse(String.new(account.one_time_keys))
    end
  end
end
