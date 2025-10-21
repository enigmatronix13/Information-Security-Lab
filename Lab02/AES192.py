from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

# AES Parameters
BLOCK_SIZE = 16  # AES block size in bytes

# Given plaintext and key
plaintext = b"Top Secret Data"
key_hex = "FEDCBA9876543210FEDCBA9876543210"  # 32 hex = 16 bytes -> AES-128
key = bytes.fromhex(key_hex)

# Pad plaintext to 16 bytes
plaintext = pad(plaintext, BLOCK_SIZE)

# Create AES cipher (ECB for showing raw AES steps)
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(plaintext)

print("Plaintext (padded):", plaintext)
print("Key (hex):", key_hex)
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())
