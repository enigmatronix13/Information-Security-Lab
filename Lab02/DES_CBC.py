'''
Encrypt the message "Secure Communication" using DES in Cipher Block Chaining (CBC) 
mode with the key "A1B2C3D4" and an initialization vector (IV) of "12345678". Provide the 
ciphertext and then decrypt it to retrieve the original message.
'''

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = b"A1B2C3D4"      # 8 bytes
iv = b"12345678"       # 8 bytes
plaintext = b"Secure Communication"

# Pad plaintext to 8-byte blocks
padded = pad(plaintext, DES.block_size)

# Encrypt
cipher_enc = DES.new(key, DES.MODE_CBC, iv=iv)
ciphertext = cipher_enc.encrypt(padded)
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt (recreate cipher)
cipher_dec = DES.new(key, DES.MODE_CBC, iv=iv)
decrypted_padded = cipher_dec.decrypt(ciphertext)
decrypted = unpad(decrypted_padded, DES.block_size)
print("Decrypted plaintext:", decrypted.decode())