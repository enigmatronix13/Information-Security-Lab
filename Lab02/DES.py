'''
Encrypt the message "Confidential Data" using DES with the following key: "A1B2C3D4". 
Then decrypt the ciphertext to verify the original message. 
'''
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Key must be 8 bytes long for DES
key = b'A1B2C3D4'  

# Data to encrypt (must be bytes)
data = b'Confidential Data'

# Create a DES cipher object in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Pad the data to be multiple of 8 bytes (DES block size)
padded_data = pad(data, DES.block_size)

# Encrypt
encrypted = cipher.encrypt(padded_data)
print("Encrypted:", encrypted.hex())

# Decrypt
decrypted_padded = cipher.decrypt(encrypted)

# Unpad the decrypted data
decrypted = unpad(decrypted_padded, DES.block_size)
print("Decrypted:", decrypted.decode())