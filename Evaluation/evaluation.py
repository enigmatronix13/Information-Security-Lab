import hashlib
import random

# ------------------------------
# RSA
# ------------------------------
def gcd(a, b):
    return a if b == 0 else gcd(b, a % b)

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def is_prime(n):
    if n < 2: return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0: return False
    return True

def generate_keys():
    # small fixed primes
    p, q = 61, 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17  # public exponent
    d = modinv(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(msg, pub):
    e, n = pub
    return [pow(ord(ch), e, n) for ch in msg]

def rsa_decrypt(cipher, priv):
    d, n = priv
    return ''.join(chr(pow(c, d, n)) for c in cipher)

# ------------------------------
# MULTIPLICATIVE CIPHER
# ------------------------------
def mul_encrypt(text, key):
    return ''.join(chr((ord(c) * key) % 256) for c in text)

def mul_decrypt(cipher, key):
    inv = modinv(key, 256)
    return ''.join(chr((ord(c) * inv) % 256) for c in cipher)

# ------------------------------
# SHA-256 
# ------------------------------
def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# ------------------------------
# CLIENT–SERVER SIMULATION
# ------------------------------
def client_server_simulation():
    print("=== CLIENT-SERVER SIMULATION ===\n")

    # Key generation (Server side)
    pub, priv = generate_keys()
    print("[SERVER] Public Key (e, n):", pub)
    print("[SERVER] Private Key (d, n):", priv)

    # Client inputs message
    message = input("\n[CLIENT] Enter message to encrypt: ")

    # Client chooses multiplicative cipher key
    key = random.choice([3, 5, 7, 11, 13, 17, 19, 23])  # must be odd
    print("[CLIENT] Multiplicative Key (k):", key)

    # Client encrypts message using multiplicative cipher
    cipher_text = mul_encrypt(message, key)
    print("[CLIENT] Ciphertext (Multiplicative Cipher):", cipher_text.encode())

    # Client encrypts key using RSA
    enc_key = rsa_encrypt(str(key), pub)
    print("[CLIENT] RSA Encrypted Key:", enc_key)

    # Client computes SHA256 hash of plaintext
    msg_hash = sha256_hash(message)
    print("[CLIENT] SHA256 Hash:", msg_hash)

    # Client sends (cipher_text, enc_key, msg_hash) to Server
    print("\n--- Data sent to Server ---")
    print("Ciphertext:", cipher_text.encode())
    print("Encrypted Key:", enc_key)
    print("SHA256 Hash:", msg_hash)
    print("---------------------------\n")

    # Server decrypts RSA to get multiplicative key
    dec_key_str = rsa_decrypt(enc_key, priv)
    dec_key = int(dec_key_str)
    print("[SERVER] Decrypted Multiplicative Key:", dec_key)

    # Server decrypts message
    decrypted_text = mul_decrypt(cipher_text, dec_key)
    print("[SERVER] Decrypted Plaintext:", decrypted_text)

    # Server verifies hash
    server_hash = sha256_hash(decrypted_text)
    print("[SERVER] SHA256 Hash (recomputed):", server_hash)
    print("[SERVER] Verification:", "Match" if server_hash == msg_hash else "Mismatch")

# ------------------------------
# MAIN
# ------------------------------
if __name__ == "__main__":
    client_server_simulation()
