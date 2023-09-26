# frozen_string_literal: true

require_relative "sha256_length_extension_attack/version"
require_relative "sha256_length_extension_attack/sha256"
require "digest"

module Sha256LengthExtensionAttack
  class Error < StandardError; end

  class << self
    def generate(extension_message, original_hash:, original_bytesize:)
      original_padding = original_bytesize == 0 ? "" : Sha256.new.generate_padding(original_bytesize * 8)
      total_bitsize = (original_bytesize + original_padding.bytesize + extension_message.bytesize) * 8
      extended_hash = Sha256.new.generate_hash(
        extension_message,
        original_hash,
        total_bitsize
      )
      [original_padding + extension_message, extended_hash]
    end
  end
end
