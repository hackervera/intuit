require "./intuit/*"
require "secure_random"
require "json"

@[Link("olm")]
lib LibOlm
  fun olm_get_library_version(major : UInt8*, minor : UInt8*, patch : UInt8*)
  fun olm_create_account(account : UInt8*, random : UInt8*, random_length : LibC::SizeT) : LibC::SizeT
  fun olm_session_size : LibC::SizeT
  fun olm_account_size : LibC::SizeT
  fun olm_utility_size : LibC::SizeT
  fun olm_create_account_random_length(account : UInt8*) : LibC::SizeT
  fun olm_account(memory : UInt8*) : UInt8*
  fun olm_session(memory : UInt8*)
  fun olm_utility(memory : UInt8*)
  fun olm_account_identity_keys_length(account : UInt8*) : LibC::SizeT
  fun olm_account_identity_keys(account : UInt8*, identity_keys : UInt8*, identity_key_length : LibC::SizeT) : LibC::SizeT
  fun olm_account_signature_length(UInt8*) : LibC::SizeT
  fun olm_account_sign(UInt8*, UInt8*, LibC::SizeT, UInt8*, LibC::SizeT) : LibC::SizeT
  fun olm_account_generate_one_time_keys_random_length(UInt8*, LibC::SizeT) : LibC::SizeT
  fun olm_account_generate_one_time_keys(UInt8*, LibC::SizeT, UInt8*, LibC::SizeT) : LibC::SizeT
  fun olm_account_one_time_keys_length(UInt8*) : LibC::SizeT
  fun olm_account_one_time_keys(UInt8*, UInt8*, LibC::SizeT) : LibC::SizeT
  fun olm_create_outbound_session_length(UInt8*) : LibC::SizeT
  fun olm_create_outbound_session(UInt8*, UInt8*, UInt8*, LibC::SizeT, UInt8*, LibC::SizeT, UInt8*, LibC::SizeT) : LibC::SizeT
  fun olm_create_inbound_session_from(UInt8*, UInt8*, UInt8*, LibC::SizeT, UInt8*, LibC::SizeT) : LibC::SizeT
  fun olm_decrypt(UInt8*, LibC::SizeT, UInt8*, LibC::SizeT, UInt8*, LibC::SizeT) : LibC::SizeT
  fun olm_decrypt_max_plaintext_length(UInt8*, LibC::SizeT, UInt8*, LibC::SizeT) : LibC::SizeT
  fun olm_error : LibC::SizeT
  fun olm_session_last_error(UInt8*) : UInt8*
  fun olm_inbound_group_session_size : LibC::SizeT
  fun olm_inbound_group_session(UInt8*) : UInt8*
  fun olm_init_inbound_group_session(UInt8*, UInt8*, LibC::SizeT) : LibC::SizeT
  fun olm_group_decrypt_max_plaintext_length(UInt8*, UInt8*, LibC::SizeT) : LibC::SizeT
  fun olm_group_decrypt(UInt8*, UInt8*, LibC::SizeT, UInt8*, LibC::SizeT, UInt32*) : LibC::SizeT
  fun olm_inbound_group_session_last_error(UInt8*) : UInt8*
end

module Intuit
  class Account
    getter :ptr, :random_length, :random, :identity_length

    def initialize(@device_id = "Intuit", @user_id = "@kodo:matrix.org")
      account_size = LibOlm.olm_account_size
      @ptr = LibOlm.olm_account(Bytes.new(account_size))
    end

    def create
      random_length = LibOlm.olm_create_account_random_length(@ptr)
      @random_length = random_length.as(LibC::SizeT)
      random = SecureRandom.random_bytes(random_length)
      @random = Slice(UInt8).new(random_length)
      # create copy for our tests
      random.copy_to @random.as(Slice(UInt8))
      LibOlm.olm_create_account(@ptr, random, random_length)
    end

    def identity_keys
      out_length = LibOlm.olm_account_identity_keys_length(@ptr)
      @identity_length = out_length.as(LibC::SizeT)
      out_buffer = Bytes.new(out_length)
      LibOlm.olm_account_identity_keys(@ptr, out_buffer, out_length)
      out_buffer
    end

    def sign(message)
      out_length = LibOlm.olm_account_signature_length(@ptr)
      out_buffer = Bytes.new(out_length)
      LibOlm.olm_account_sign(@ptr, message, message.bytesize, out_buffer, out_length)
      out_buffer
    end

    def one_time_keys
      out_length = LibOlm.olm_account_one_time_keys_length(@ptr)
      out_buffer = Bytes.new(out_length)
      LibOlm.olm_account_one_time_keys(@ptr, out_buffer, out_length)
      out_buffer
    end

    def generate_one_time_keys(count)
      random_length = LibOlm.olm_account_generate_one_time_keys_random_length(@ptr, count)
      random = SecureRandom.random_bytes(random_length)
      LibOlm.olm_account_generate_one_time_keys(@ptr, count, random, random_length)
    end

    def to_json
      keys = JSON.parse(String.new(identity_keys))
      key_hash = {"algorithms" => ["m.megolm.v1.aes-sha2", "m.olm.v1.curve25519-aes-sha2"],
        "device_id"  => @device_id,
        "keys"       => {"curve25519:#{@device_id}" => keys["curve25519"].to_s, "ed25519:#{@device_id}" => keys["ed25519"].to_s},

        "user_id" => @user_id,
      } of String => Array(String) | Hash(String, String) | String | Hash(String, Hash(String, String))
      signature = sign key_hash.to_json
      device_key = "ed25519:#{@device_id}"
      signatures = {@user_id => {device_key => String.new(signature)}}
      # puts signatures
      key_hash["signatures"] = signatures

      # {key_type => {key_id => key}}
      otks = String.new(one_time_keys)
      otks = Hash(String, Hash(String, String)).from_json(otks)
      # puts otks

      otk_hsh = Hash(String, Hash(String, Hash(String, Hash(String, String)) | String)).new
      otks.keys.each do |key_type|
        otks[key_type].to_h.keys.each do |key_id|
          key = otks[key_type].to_h[key_id].to_s
          key_obj = {"key" => key}.to_json
          signature = String.new(sign(key_obj))
          otk_hsh["signed_curve25519:#{key_id}"] = {"key" => key, "signatures" => {@user_id => {"ed25519:#{@device_id}" => signature}}}
        end
      end
      output = {"device_keys" => key_hash, "one_time_keys" => otk_hsh}
      output.to_json
    end
  end

  class InboundGroupSession
    property :message_index
    @message_index : UInt32

    def initialize(session_key, message_index = 0)
      @message_index = message_index.to_u32
      buffer = Bytes.new(LibOlm.olm_inbound_group_session_size)
      @ptr = LibOlm.olm_inbound_group_session(buffer)
      response = LibOlm.olm_init_inbound_group_session(@ptr, session_key, session_key.bytesize)
    end

    def decrypt(message)
      message = message.to_s
      msg_copy = String.new(message.to_slice)
      max_length = LibOlm.olm_group_decrypt_max_plaintext_length(@ptr, message, message.bytesize)
      buffer = Bytes.new(max_length)
      buffer_length = LibOlm.olm_group_decrypt(@ptr, msg_copy, message.bytesize, buffer, max_length, pointerof(@message_index))
      String.new(buffer[0, buffer_length])
    end
  end

  class Session
    def initialize
      @ptr = Bytes.new(LibOlm.olm_session_size)
      LibOlm.olm_session(@ptr)
    end

    def create_inbound_from(account, identity_key, otk_msg)
      puts LibOlm.olm_create_inbound_session_from(@ptr, account.ptr, identity_key, identity_key.bytesize, otk_msg, otk_msg.bytesize)
    end

    def decrypt(message_type, message)
      msg_copy = String.new(message.to_slice)
      max_length = LibOlm.olm_decrypt_max_plaintext_length(@ptr, message_type, message, message.bytesize)
      buffer = Bytes.new(max_length)
      buffer_length = LibOlm.olm_decrypt(@ptr, message_type, msg_copy, message.bytesize, buffer, max_length)
      String.new(buffer[0, buffer_length])
    end

    #   def create_outbound(account, identity_key, one_time_key)
    #     rand_length = LibOlm.olm_create_outbound_session_random_length(@ptr)
    #     random = SecureRandom.random_bytes(rand_length)
    #     LibOlm.olm_create_outbound_session(@ptr, account.ptr, identity_key, one_time_key, random, rand_length)
    #   end
  end
end
