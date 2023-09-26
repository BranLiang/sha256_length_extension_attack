class Sha256
  K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ].freeze

  def generate_hash(extended_message, original_hash, total_length_in_bits)
    # 1. Initialize hash values
    h = original_hash.scan(/.{8}/).map { |chunk| chunk.to_i(16) }

    # 2. Pre-processing
    message = padding(extended_message, total_length_in_bits)

    # 3. Process the message in successive 512-bit chunks
    split_message_to_blocks(message).each do |message_block|
      h = process_message_block(message_block, h)
    end

    # 4. Produce the final hash value (big-endian)
    h.map { |hi| hi.to_s(16).rjust(8, "0") }.join
  end

  def generate_padding(length)
    p = padding("x" * (length / 8), length)
    p[length / 8..-1]
  end

  private

  # CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
  def ch(x, y, z)
    (x & y) ^ ((~x) & z)
  end

  # MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
  def maj(x, y, z)
    (x & y) ^ (x & z) ^ (y & z)
  end

  # ROTR( x, n) = (x >> n) OR (x << (32 - n))
  def rotr(x, n)
    (x >> n) | (x << (32 - n))
  end

  # SHR( x, n) = x >> n
  def shr(x, n)
    x >> n
  end

  # BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
  def bsig0(x)
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
  end

  # BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
  def bsig1(x)
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
  end

  # SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
  def ssig0(x)
    rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)
  end

  # SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
  def ssig1(x)
    rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)
  end

  def padding(message, length_in_bits)
    message = message.dup
    # 1. append "1" bit to message
    message << [0x80].pack("C")

    # 2. append "0" bits until message length in bits ≡ 448 (mod 512)
    # 448 = 56 * 8
    while message.bytesize % 64 != 56
      message << [0x00].pack("C")
    end

    # 3. append length of message in bits as 64-bit big-endian integer
    message << [length_in_bits].pack("Q>")

    message
  end

  # Split message into 512-bit blocks
  def split_message_to_blocks(message)
    message.bytes.each_slice(64).map { |block| block.pack("C*") }
  end

  def process_message_block(message_block, hash)
    # 1. Prepare the message schedule
    w = []
    (0..15).each do |t|
      w[t] = message_block[t * 4, 4].unpack1("N")
    end
    (16..63).each do |t|
      w[t] = (ssig1(w[t - 2]) + w[t - 7] + ssig0(w[t - 15]) + w[t - 16]) % 2**32
    end

    # 2. Initialize the eight working variables with the (i-1)st hash value
    a, b, c, d, e, f, g, h = hash

    # 3. Perform the main hash computation
    (0..63).each do |t|
      t1 = (h + bsig1(e) + ch(e, f, g) + K[t] + w[t]) % 2**32
      t2 = (bsig0(a) + maj(a, b, c)) % 2**32
      h = g
      g = f
      f = e
      e = (d + t1) % 2**32
      d = c
      c = b
      b = a
      a = (t1 + t2) % 2**32
    end

    # 4. Compute the intermediate hash value
    [
      (a + hash[0]) % 2**32,
      (b + hash[1]) % 2**32,
      (c + hash[2]) % 2**32,
      (d + hash[3]) % 2**32,
      (e + hash[4]) % 2**32,
      (f + hash[5]) % 2**32,
      (g + hash[6]) % 2**32,
      (h + hash[7]) % 2**32,
    ]
  end
end
