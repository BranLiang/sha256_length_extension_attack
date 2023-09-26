# frozen_string_literal: true

require_relative "sha256_length_extension_attack/version"
require_relative "sha256_length_extension_attack/sha256"
require "digest"

module Sha256LengthExtensionAttack
  class Error < StandardError; end

  class << self
    def generate_padding(length)
      Sha256.new.generate_padding(length)
    end

    def generate_hash(extension_message, original_hash:, total_length:)
      Sha256.new.generate_hash(
        extension_message,
        original_hash,
        total_length
      )
    end
  end
end
