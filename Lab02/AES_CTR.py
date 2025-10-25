'''
Encrypt the message "Cryptography Lab Exercise" using AES in Counter (CTR) mode with 
the key "0123456789ABCDEF0123456789ABCDEF" and a nonce of "0000000000000000". 
Provide the ciphertext and then decrypt it to retrieve the original message.
'''
from Crypto.Cipher import AES
from Crypto.Util import Counter

# Key and nonce are provided as hex strings
key_hex = "0123456789ABCDEF0123456789ABCDEF"
nonce_hex = "0000000000000000"

key = bytes.fromhex(key_hex)      # 16 bytes (128-bit key)
nonce = bytes.fromhex(nonce_hex)  # 8 bytes (64-bit nonce)

# Build a counter: 64-bit counter, 64-bit prefix = nonce (total 128 bits)
ctr_encrypt = Counter.new(64, prefix=nonce, initial_value=0)
cipher_enc = AES.new(key, AES.MODE_CTR, counter=ctr_encrypt)

plaintext = b"Cryptography Lab Exercise"
ciphertext = cipher_enc.encrypt(plaintext)

print("Ciphertext (hex):", ciphertext.hex())

# For decryption recreate the same counter (same nonce and initial_value)
ctr_decrypt = Counter.new(64, prefix=nonce, initial_value=0)
cipher_dec = AES.new(key, AES.MODE_CTR, counter=ctr_decrypt)
decrypted = cipher_dec.decrypt(ciphertext)

print("Decrypted plaintext:", decrypted.decode())