from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

'''
Encrypt the following block of data using DES with the key "A1B2C3D4E5F60708". The data 
to be encrypted is: Mathematica   
Block1: 54686973206973206120636f6e666964656e7469616c206d657373616765   
Block2: 416e64207468697320697320746865207365636f6e6420626c6f636b   
a. Provide the ciphertext for each block. 
b. Decrypt the ciphertext to retrieve the original plaintext blocks.
'''

key_hex = "A1B2C3D4E5F60708"
key = bytes.fromhex(key_hex)  # 8 bytes DES key

block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"
block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"

def encrypt_decrypt_block(block_hex):
    data = bytes.fromhex(block_hex)
    padded = False
    if len(data) % DES.block_size != 0:
        data = pad(data, DES.block_size)
        padded = True

    cipher = DES.new(key, DES.MODE_ECB)
    ct = cipher.encrypt(data)
    print("Ciphertext (hex):", ct.hex())

    # Decrypt
    plain_p = DES.new(key, DES.MODE_ECB).decrypt(ct)
    if padded:
        plain_p = unpad(plain_p, DES.block_size)
    try:
        print("Decrypted plaintext:", plain_p.decode())
    except UnicodeDecodeError:
        print("Decrypted plaintext (raw):", plain_p)

print("Block 1:")
encrypt_decrypt_block(block1_hex)
print("\nBlock 2:")
encrypt_decrypt_block(block2_hex)

