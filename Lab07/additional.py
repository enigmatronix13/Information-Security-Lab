'''
Implement similar exercise for other PHE operations (like homomorphic multiplication using ElGamal)
or explore different functionalities within Paillier.
1a: Homomorphic Multiplication (ElGamal Cryptosystem): Implement ElGamal encryption
and demonstrate homomorphic multiplication on encrypted messages. (ElGamal supports
multiplication but not homomorphic addition.)
1b: Secure Data Sharing (Paillier): Simulate a scenario where two parties share encrypted data
and perform calculations on the combined data without decryption.
1c: Secure Thresholding (PHE): Explore how PHE can be used for secure multi-party
computation, where a certain number of parties need to collaborate on a computation without
revealing their individual data.
1d: Performance Analysis (Benchmarking): Compare the performance of different PHE
schemes (Paillier and ElGamal) for various operations.
'''

import random

# Large prime p and generator g (selected for simplicity)
p = 467
g = 2

# Private key x and public key h = g^x mod p
x = random.randint(1, p-2)
h = pow(g, x, p)

def encrypt(m):
    y = random.randint(1, p-2)
    c1 = pow(g, y, p)
    c2 = (m * pow(h, y, p)) % p
    return (c1, c2)

def decrypt(c):
    c1, c2 = c
    s = pow(c1, x, p)
    s_inv = pow(s, p-2, p)  # Modular inverse via Fermat's little theorem since p is prime
    m = (c2 * s_inv) % p
    return m

# Encrypt two messages
m1, m2 = 7, 3
c1 = encrypt(m1)
c2 = encrypt(m2)

print("Ciphertext for 7:", c1)
print("Ciphertext for 3:", c2)

# Homomorphic multiplication (multiply ciphertext components modulo p)
c1_mul = (c1[0] * c2[0]) % p
c2_mul = (c1[1] * c2[1]) % p
c_mul = (c1_mul, c2_mul)

print("Ciphertext of multiplication:", c_mul)

# Decrypt the result
m_mul = decrypt(c_mul)
print("Decrypted multiplication result:", m_mul)

# Verify correctness
print("Expected multiplication result:", (m1 * m2) % p)

# Homomorphic exponentiation demonstration
c1_pow = pow(c1[0], 3, p)
c2_pow = pow(c1[1], 3, p)
c_pow = (c1_pow, c2_pow)
print("Decrypted m1^3:", decrypt(c_pow))
