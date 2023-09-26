# SHA-256 Length Extension Attack Demo

This is a simple Ruby library designed to demonstrate a [length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack) on the SHA-256 hash algorithm.

## Installation

```shell
gem install sha256_length_extension_attack
```

## Usage
The original hash is calculated using the following process:

```ruby
secret = "SOMETHING_YOU_DONT_KNOW"
Digest::SHA256.hexdigest(secret + "::" + "name=bran")
```

The original hash value is: `10b8813fba3378e9cb6ecec95ab471cea46b09eb93607d0851e07e89390e4758`.

Now, let's say you want to tamper with the message and add an additional query parameter `admin=true` at the end. Since you don't know the exact content of the secret, you cannot generate the new hash directly. However, it's possible to guess the length of the password, and in the worst case, you may need to try several possible lengths. Let's assume you now know that the length of the password is `10`, making the original message byte size `21`. We'll call this value `original_bytesize`. You can use the following method to generate a new hash, including the original message, even though you still don't know the secret:

```ruby
suffix, hash = Sha256LengthExtensionAttack.generate(
    "admin=true",
    original_hash: "10b8813fba3378e9cb6ecec95ab471cea46b09eb93607d0851e07e89390e4758",
    original_bytesize: 21
)
```

If you inspect the `suffix` variable, you'll notice that it contains a sequence of bits before our targeted content. These bits are typically referred to as padding when hashing normally. However, in this case, we treat them as part of the normal message.

```ruby
\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xA8&admin=true
```

The `hash` variable contains the resulting hash value, which you would normally generate using `Digest::SHA256.hexdigest(message)`.

Congratulations, you have successfully completed a SHA-256 length extension attack!

## License

This library is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
