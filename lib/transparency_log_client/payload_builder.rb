# frozen_string_literal: true

require "json"
require "openssl"
require "base64"

module Tlog
  class PayloadBuilder

    # hashrekord payload
    def self.build(json_payload)
      raw        = JSON.dump(json_payload)
      key        = load_private_key
      signature  = sign(key, raw)
      public_key = key.public_key.to_pem

      {
        "kind"       => "hashedrekord",
        "apiVersion" => "0.0.1",
        "spec"       => {
          "data"      => {
            "hash" => {
              "algorithm" => "sha256",
              "value"     => hex_digest(raw)
            }
          },
          "signature" => {
            "content"   => base64_encode(signature),
            "publicKey" => {
              "content" => base64_encode(public_key)
            }
          }
        }
      }
    end

    private

    def self.load_private_key
      pem = "placeholder" #Rails.application.credentials.dig(:tlog, :private_key)
      OpenSSL::PKey::EC.new(pem)
    end

    def self.sign(key, data)
      key.sign(OpenSSL::Digest::SHA256.new, data)
    end

    def self.hex_digest(data)
      OpenSSL::Digest::SHA256.hexdigest(data)
    end

    def self.base64_encode(data)
      Base64.strict_encode64(data)
    end
  end
end