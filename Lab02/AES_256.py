from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
key = bytes.fromhex(key_hex)           # 32 bytes => AES-256
iv = bytes(16)                         # 16-byte zero IV (deterministic for demo)

plaintext = b"Encryption Strength"
padded = pad(plaintext, AES.block_size)

# Encrypt
cipher_enc = AES.new(key, AES.MODE_CBC, iv=iv)
ciphertext = cipher_enc.encrypt(padded)
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt
cipher_dec = AES.new(key, AES.MODE_CBC, iv=iv)
decrypted_padded = cipher_dec.decrypt(ciphertext)
decrypted = unpad(decrypted_padded, AES.block_size)
print("Decrypted plaintext:", decrypted.decode())