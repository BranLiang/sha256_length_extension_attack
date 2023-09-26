# frozen_string_literal: true

require "test_helper"

class TestSha256LengthExtensionAttack < Minitest::Test
  def setup
    original_password = "itsasecret"
    original_message = "name=bran"
    @payload = original_password + "::" + original_message
    @original_hash = Digest::SHA256.hexdigest(@payload)
    puts "Original hash: #{@original_hash}"
  end

  def test_generate
    extended_message = "&admin=true"
    padding = Sha256.new.generate_padding(@payload.bytesize * 8)

    tampered_message = @payload + padding + extended_message

    expected_hash = Digest::SHA256.hexdigest(tampered_message)
    suffix, extended_hash = Sha256LengthExtensionAttack.generate(
      extended_message,
      original_hash: @original_hash,
      original_bytesize: @payload.bytesize
    )
    assert_equal(
      expected_hash,
      extended_hash
    )
    assert_equal(
      '"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xA8&admin=true"',
      suffix.inspect
    )
  end

  def test_generate_empty_original_payload
    initial_hash = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"
    _, result_hash = Sha256LengthExtensionAttack.generate(
      @payload,
      original_hash: initial_hash,
      original_bytesize: 0
    )
    assert_equal(
      @original_hash,
      result_hash
    )
  end
end
