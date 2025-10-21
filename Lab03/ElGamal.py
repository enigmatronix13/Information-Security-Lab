import random
from sympy import nextprime

# Convert string to int
def msg_to_int(msg):
    return int.from_bytes(msg.encode('utf-8'), 'big')

# Convert int back to string
def int_to_msg(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big').decode('utf-8')

# Modular inverse (Extended Euclidean Algorithm)
def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# Generate keys with prime p > message integer
def generate_keys(msg_int):
    # Find prime p larger than twice the message integer to avoid wrap-around
    p = nextprime(msg_int * 2)
    g = 2  # Usually 2 is a suitable generator for safe primes

    x = random.randint(2, p - 2)  # Private key
    h = pow(g, x, p)  # Public key h = g^x mod p

    return (p, g, h), x

# ElGamal encryption
def elgamal_encrypt(pubkey, msg_int):
    p, g, h = pubkey
    k = random.randint(2, p - 2)  # Ephemeral key

    c1 = pow(g, k, p)
    s = pow(h, k, p)
    c2 = (msg_int * s) % p
    return c1, c2

# ElGamal decryption
def elgamal_decrypt(privkey, pubkey, c1, c2):
    p, _, _ = pubkey
    x = privkey

    s = pow(c1, x, p)
    s_inv = modinv(s, p)
    m = (c2 * s_inv) % p
    return m

if __name__ == "__main__":
    message = "Confidential Data"
    print(f"Original message: {message}")

    msg_int = msg_to_int(message)
    print(f"Message as integer: {msg_int}")

    pubkey, privkey = generate_keys(msg_int)
    p, g, h = pubkey

    print(f"Generated public key (p, g, h):\n p = {p}\n g = {g}\n h = {h}")
    print(f"Private key x = {privkey}")

    c1, c2 = elgamal_encrypt(pubkey, msg_int)
    print(f"Ciphertext:\n c1 = {c1}\n c2 = {c2}")

    decrypted_int = elgamal_decrypt(privkey, pubkey, c1, c2)
    decrypted_msg = int_to_msg(decrypted_int)
    print(f"Decrypted message: {decrypted_msg}")