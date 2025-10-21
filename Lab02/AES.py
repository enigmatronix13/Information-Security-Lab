from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Given key (hex string) - AES-128 needs a 16-byte key, so we'll take the first 16 bytes
key_hex = "0123456789ABCDEF0123456789ABCDEF"
key = bytes.fromhex(key_hex)[:16]  # Take first 16 bytes for AES-128

# Message to encrypt
plaintext = "Sensitive Information".encode()

# AES block size is 16 bytes
block_size = 16

# Create cipher in ECB mode (for simplicity)
cipher = AES.new(key, AES.MODE_ECB)

# Pad plaintext to block size and encrypt
ciphertext = cipher.encrypt(pad(plaintext, block_size))

print("Ciphertext:", ciphertext.hex())

# Decrypt
decipher = AES.new(key, AES.MODE_ECB)
decrypted_padded = decipher.decrypt(ciphertext)
decrypted = unpad(decrypted_padded, block_size)

print("Decrypted message:", decrypted.decode())