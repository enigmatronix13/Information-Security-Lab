'''
Utilize the multiplicative homomorphic property of RSA encryption. Implement a basic
RSA encryption scheme in Python. Encrypt two integers (e.g., 7 and 3) using your
implementation of the RSA encryption scheme. Print the ciphertexts. Perform a
multiplication operation on the encrypted integers without decrypting them. Print the result
of the multiplication in encrypted form. Decrypt the result of the multiplication and verify
that it matches the product of the original integers.
'''

import math

# Helper to compute modular inverse
def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y

# RSA key generation
p = 61
q = 53
n = p * q
phi = (p - 1) * (q - 1)

e = 17
d = modinv(e, phi)

# RSA encryption
def encrypt(m, e, n):
    return pow(m, e, n)

# RSA decryption
def decrypt(c, d, n):
    return pow(c, d, n)

# Encrypt two numbers
m1 = 7
m2 = 3

c1 = encrypt(m1, e, n)
c2 = encrypt(m2, e, n)

print("Ciphertext for 7:", c1)
print("Ciphertext for 3:", c2)

# Multiplicative homomorphism: encrypted multiplication
enc_product = (c1 * c2) % n
print("Result of encrypted multiplication:", enc_product)

# Decrypt result
decrypted_product = decrypt(enc_product, d, n)
print("Decrypted product:", decrypted_product)
