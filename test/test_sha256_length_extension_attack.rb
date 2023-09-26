# frozen_string_literal: true

require "test_helper"

class TestSha256LengthExtensionAttack < Minitest::Test
  def setup
    original_password = "itsasecret"
    original_message = "name=bran"
    @payload = original_password + "::" + original_message
    @original_hash = Digest::SHA256.hexdigest(@payload)
  end

  def test_generate_hash
    extended_message = "&admin=true"
    padding = Sha256LengthExtensionAttack.generate_padding(@payload.bytesize * 8)

    tampered_message = @payload + padding + extended_message

    expected_hash = Digest::SHA256.hexdigest(tampered_message)
    extended_hash = Sha256LengthExtensionAttack.generate_hash(
      extended_message,
      original_hash: @original_hash,
      total_length: tampered_message.bytesize * 8
    )
    assert_equal(
      expected_hash,
      extended_hash
    )
  end

  def test_generate_padding
    initial_hash = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"
    assert_equal(
      @original_hash,
      Sha256LengthExtensionAttack.generate_hash(
        @payload,
        original_hash: initial_hash,
        total_length: @payload.bytesize * 8
      )
    )
  end
end
