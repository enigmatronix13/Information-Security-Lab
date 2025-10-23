'''
Implement the Paillier encryption scheme in Python. Encrypt two integers (e.g., 15 and 25)
using your implementation of the Paillier encryption scheme. Print the ciphertexts. Perform
an addition operation on the encrypted integers without decrypting them. Print the result of
the addition in encrypted form. Decrypt the result of the addition and verify that it matches
the sum of the original integers.
'''

from phe import paillier

# Generate public and private keys
public_key, private_key = paillier.generate_paillier_keypair()

# Choose two integers to encrypt
a = 15
b = 25

# Encrypt both integers
encrypted_a = public_key.encrypt(a)
encrypted_b = public_key.encrypt(b)

# Display the ciphertexts
print("Ciphertext for 15:", encrypted_a.ciphertext())
print("Ciphertext for 25:", encrypted_b.ciphertext())

# Homomorphic addition of encrypted integers
encrypted_sum = encrypted_a + encrypted_b
print("Ciphertext for homomorphic addition (15 + 25):", encrypted_sum.ciphertext())

# Decrypt the result
decrypted_sum = private_key.decrypt(encrypted_sum)
print("Decrypted sum:", decrypted_sum)