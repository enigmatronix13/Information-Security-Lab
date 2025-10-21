from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# Message and key
message = b"Classified Text"
key = b"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"  # 48 bytes

# 3DES requires 16 or 24 bytes key, not 48. We'll truncate to 24 (most standard implementations do this).
key = key[:24]

# Ensure key is valid (DES3 keys must have odd parity)
while True:
    try:
        cipher = DES3.new(key, DES3.MODE_ECB)
        break
    except ValueError:
        # If parity issue, tweak last byte slightly
        key = key[:-1] + bytes([(key[-1] ^ 1)])

# Encrypt
cipher = DES3.new(key, DES3.MODE_ECB)
ciphertext = cipher.encrypt(pad(message, DES3.block_size))

# Decrypt
decipher = DES3.new(key, DES3.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), DES3.block_size)

# Output
print("Original Message:", message.decode())
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted Message:", decrypted.decode())