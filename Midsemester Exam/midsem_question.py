import hashlib
import random
from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
import json

# ===============================================================
# RSA ENCRYPTION / DECRYPTION
# ===============================================================
def generate_rsa_keys(bits=512):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p-1)*(q-1)
    e = 65537
    d = inverse(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(m, pubkey):
    e, n = pubkey
    c = pow(m, e, n)
    return c

def rsa_decrypt(c, privkey):
    d, n = privkey
    m = pow(c, d, n)
    return m

# ===============================================================
# ROW + COLUMNAR TRANSPOSITION CIPHERS 
# ===============================================================
def row_transposition_encrypt(text, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    num_cols = len(key)
    num_rows = len(text) // num_cols + (len(text) % num_cols != 0)
    matrix = [[' ' for _ in range(num_cols)] for _ in range(num_rows)]

    idx = 0
    for r in range(num_rows):
        for c in range(num_cols):
            if idx < len(text):
                matrix[r][c] = text[idx]
                idx += 1

    ciphertext = ''
    for c in key_order:
        for r in range(num_rows):
            ciphertext += matrix[r][c]
    return ciphertext.strip()

def row_transposition_decrypt(ciphertext, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    num_cols = len(key)
    num_rows = len(ciphertext) // num_cols + (len(ciphertext) % num_cols != 0)
    matrix = [['' for _ in range(num_cols)] for _ in range(num_rows)]

    idx = 0
    for c in key_order:
        for r in range(num_rows):
            if idx < len(ciphertext):
                matrix[r][c] = ciphertext[idx]
                idx += 1

    plaintext = ''
    for r in range(num_rows):
        for c in range(num_cols):
            plaintext += matrix[r][c]
    return plaintext.strip()

def columnar_transposition_encrypt(text, key):
    num_cols = len(key)
    num_rows = len(text) // num_cols + (len(text) % num_cols != 0)
    matrix = [[' ' for _ in range(num_cols)] for _ in range(num_rows)]

    idx = 0
    for c in range(num_cols):
        for r in range(num_rows):
            if idx < len(text):
                matrix[r][c] = text[idx]
                idx += 1

    key_order = sorted(range(len(key)), key=lambda k: key[k])
    ciphertext = ''
    for r in range(num_rows):
        for c in key_order:
            ciphertext += matrix[r][c]
    return ciphertext.strip()

def columnar_transposition_decrypt(ciphertext, key):
    num_cols = len(key)
    num_rows = len(ciphertext) // num_cols + (len(ciphertext) % num_cols != 0)
    matrix = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    idx = 0

    # fill column-wise according to key order
    for r in range(num_rows):
        for c in key_order:
            if idx < len(ciphertext):
                matrix[r][c] = ciphertext[idx]
                idx += 1

    plaintext = ''
    for c in range(num_cols):
        for r in range(num_rows):
            plaintext += matrix[r][c]
    return plaintext.strip()

# ===============================================================
# ELGAMAL DIGITAL SIGNATURE
# ===============================================================
def generate_elgamal_keys(bits=256):
    p = getPrime(bits)
    g = random.randint(2, p-2)
    x = random.randint(1, p-2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_sign(message_hash_int, privkey, pubkey):
    p, g, y = pubkey
    x = privkey
    while True:
        k = random.randint(1, p-2)
        if GCD(k, p-1) == 1:
            break
    r = pow(g, k, p)
    k_inv = inverse(k, p-1)
    s = (k_inv * (message_hash_int - x*r)) % (p-1)
    return (r, s)

def elgamal_verify(message_hash_int, signature, pubkey):
    p, g, y = pubkey
    r, s = signature
    if not (0 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, message_hash_int, p)
    return v1 == v2

# ===============================================================
# CLIENT FUNCTION
# ===============================================================
def client():
    print("\n=== CLIENT SIDE ===")

    M = input("Enter message M: ")

    # RSA
    pub_rsa, priv_rsa = generate_rsa_keys()
    rsa_cipher = rsa_encrypt(bytes_to_long(M.encode()), pub_rsa)
    print(f"\n[CLIENT] RSA Encrypted Message: {rsa_cipher}")

    # SHA-256
    sha_hash = hashlib.sha256(M.encode()).hexdigest()
    print(f"[CLIENT] SHA-256 Hash: {sha_hash}")

    # Row + Columnar Transposition
    row_key = "31524"
    col_key = "4312"
    after_row = row_transposition_encrypt(sha_hash, row_key)
    after_col = columnar_transposition_encrypt(after_row, col_key)
    print(f"[CLIENT] After Row + Columnar Transposition: {after_col}")

    # ElGamal Digital Signature
    pub_elg, priv_elg = generate_elgamal_keys()
    message_hash_int = int(hashlib.sha256(M.encode()).hexdigest(), 16)
    signature = elgamal_sign(message_hash_int, priv_elg, pub_elg)
    print(f"[CLIENT] ElGamal Signature: {signature}")

    # Bundle all to send
    packet = {
        'rsa_cipher': rsa_cipher,
        'hash_transposed': after_col,
        'signature': signature,
        'pub_elg': pub_elg,
        'pub_rsa': pub_rsa,
        'row_key': row_key,
        'col_key': col_key
    }

    return json.dumps(packet), priv_rsa, M

# ===============================================================
# SERVER FUNCTION
# ===============================================================
def server(packet_json, priv_rsa, original_message):
    print("\n=== SERVER SIDE ===")

    data = json.loads(packet_json)
    rsa_cipher = data['rsa_cipher']
    signature = tuple(data['signature'])
    pub_elg = tuple(data['pub_elg'])
    row_key = data['row_key']
    col_key = data['col_key']

    # Verify signature
    message_hash_int = int(hashlib.sha256(original_message.encode()).hexdigest(), 16)
    verified = elgamal_verify(message_hash_int, signature, pub_elg)

    if verified:
        print("[SERVER] ElGamal Signature Verified.")
        decrypted_int = rsa_decrypt(rsa_cipher, priv_rsa)
        decrypted_message = long_to_bytes(decrypted_int).decode()
        print(f"[SERVER] RSA Decrypted Message: {decrypted_message}")

        # Reverse transposition decryption
        received_hash_transposed = data['hash_transposed']
        after_col_decrypt = columnar_transposition_decrypt(received_hash_transposed, col_key)
        after_row_decrypt = row_transposition_decrypt(after_col_decrypt, row_key)
        print(f"[SERVER] Recovered Hash After Decryption: {after_row_decrypt}")

        # Compare with recomputed SHA-256 of decrypted message
        recomputed_hash = hashlib.sha256(decrypted_message.encode()).hexdigest()
        print(f"[SERVER] Recomputed SHA-256: {recomputed_hash}")

        if recomputed_hash == after_row_decrypt:
            print("[SERVER] Hash Integrity Verified – Message Untampered.")
        else:
            print("[SERVER] Hash Mismatch – Message May Be Altered.")
    else:
        print("[SERVER] Signature Verification Failed!")

# ===============================================================
# MAIN
# ===============================================================
if __name__ == "__main__":
    packet, priv_rsa, M = client()
    server(packet, priv_rsa, M)