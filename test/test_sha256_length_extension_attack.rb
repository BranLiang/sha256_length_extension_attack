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
    extension_message = "&admin=true"
    extension_hash = Sha256LengthExtensionAttack.generate_hash(@original_hash, extension_message)
    expected_hash = Digest::SHA256.hexdigest(@payload + extension_message)
    assert_equal(
      expected_hash,
      extension_hash
    )
  end
end
