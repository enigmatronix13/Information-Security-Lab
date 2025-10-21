import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import secrets

# Helper: AES-GCM encrypt/decrypt file in chunks
def aes_gcm_encrypt_file(aes_key, iv, infile, outfile):
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    with open(infile, 'rb') as fin, open(outfile, 'wb') as fout:
        while True:
            chunk = fin.read(64*1024)  # 64KB chunks
            if not chunk:
                break
            encrypted_chunk = encryptor.update(chunk)
            fout.write(encrypted_chunk)
        encryptor.finalize()
        fout.write(encryptor.tag)  # append tag at the end

def aes_gcm_decrypt_file(aes_key, iv, infile, outfile):
    with open(infile, 'rb') as fin:
        filesize = os.path.getsize(infile)
        tag_size = 16  # GCM tag size
        ciphertext_len = filesize - tag_size
        ciphertext = fin.read(ciphertext_len)
        tag = fin.read(tag_size)

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    with open(outfile, 'wb') as fout:
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        fout.write(decrypted)

# RSA key generation
def generate_rsa_keys():
    start = time.time()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    end = time.time()
    return private_key, end - start

# RSA encrypt AES key
def rsa_encrypt(public_key, data):
    start = time.time()
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    end = time.time()
    return encrypted, end - start

# RSA decrypt AES key
def rsa_decrypt(private_key, encrypted):
    start = time.time()
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    end = time.time()
    return decrypted, end - start

# ECC key generation
def generate_ecc_keys():
    start = time.time()
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    end = time.time()
    return private_key, end - start

# ECC encrypt AES key via ECDH + AES-GCM (ephemeral keys)
def ecc_encrypt(public_key, data):
    start = time.time()
    # Generate ephemeral private key
    ephemeral_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)

    # Derive symmetric key from shared_key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    # Encrypt data (AES-GCM) with derived key
    iv = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # Serialize ephemeral public key to send along
    ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    end = time.time()
    # Return ephemeral public key, iv, ciphertext, tag, and encryption time
    return (ephemeral_public_bytes, iv, ciphertext, encryptor.tag), end - start

# ECC decrypt AES key via ECDH + AES-GCM
def ecc_decrypt(private_key, ephemeral_public_bytes, iv, ciphertext, tag):
    start = time.time()
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_public_bytes)
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    decryptor = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    end = time.time()
    return decrypted, end - start

# Generate random AES key
def generate_aes_key():
    return secrets.token_bytes(32)  # AES-256 key

# Main benchmarking and file encryption test
def run_test(file_path):
    print(f"\n--- Testing with file: {file_path} ---")
    filesize = os.path.getsize(file_path)
    print(f"File size: {filesize / (1024*1024):.2f} MB")

    # 1. Generate RSA keys
    rsa_priv, rsa_keygen_time = generate_rsa_keys()
    rsa_pub = rsa_priv.public_key()
    print(f"RSA 2048 key generation time: {rsa_keygen_time:.4f} s")

    # 2. Generate ECC keys
    ecc_priv, ecc_keygen_time = generate_ecc_keys()
    ecc_pub = ecc_priv.public_key()
    print(f"ECC secp256r1 key generation time: {ecc_keygen_time:.4f} s")

    # Generate AES key & IV
    aes_key = generate_aes_key()
    iv = secrets.token_bytes(12)

    # --- RSA hybrid encryption ---

    # Encrypt AES key with RSA
    encrypted_aes_key_rsa, rsa_enc_key_time = rsa_encrypt(rsa_pub, aes_key)
    print(f"RSA AES key encryption time: {rsa_enc_key_time:.4f} s")

    # Encrypt file with AES
    start = time.time()
    aes_gcm_encrypt_file(aes_key, iv, file_path, "encrypted_rsa.bin")
    rsa_file_enc_time = time.time() - start
    print(f"RSA hybrid AES file encryption time: {rsa_file_enc_time:.4f} s")

    # --- RSA hybrid decryption ---

    # Decrypt AES key with RSA
    decrypted_aes_key_rsa, rsa_dec_key_time = rsa_decrypt(rsa_priv, encrypted_aes_key_rsa)
    print(f"RSA AES key decryption time: {rsa_dec_key_time:.4f} s")

    # Decrypt file with AES
    start = time.time()
    aes_gcm_decrypt_file(decrypted_aes_key_rsa, iv, "encrypted_rsa.bin", "decrypted_rsa.bin")
    rsa_file_dec_time = time.time() - start
    print(f"RSA hybrid AES file decryption time: {rsa_file_dec_time:.4f} s")

    # --- ECC hybrid encryption ---

    # Encrypt AES key with ECC
    (ephemeral_pub, ecc_iv, ecc_ciphertext, ecc_tag), ecc_enc_key_time = ecc_encrypt(ecc_pub, aes_key)
    print(f"ECC AES key encryption time: {ecc_enc_key_time:.4f} s")

    # Encrypt file with AES
    start = time.time()
    aes_gcm_encrypt_file(aes_key, iv, file_path, "encrypted_ecc.bin")
    ecc_file_enc_time = time.time() - start
    print(f"ECC hybrid AES file encryption time: {ecc_file_enc_time:.4f} s")

    # --- ECC hybrid decryption ---

    # Decrypt AES key with ECC
    decrypted_aes_key_ecc, ecc_dec_key_time = ecc_decrypt(ecc_priv, ephemeral_pub, ecc_iv, ecc_ciphertext, ecc_tag)
    print(f"ECC AES key decryption time: {ecc_dec_key_time:.4f} s")

    # Decrypt file with AES
    start = time.time()
    aes_gcm_decrypt_file(decrypted_aes_key_ecc, iv, "encrypted_ecc.bin", "decrypted_ecc.bin")
    ecc_file_dec_time = time.time() - start
    print(f"ECC hybrid AES file decryption time: {ecc_file_dec_time:.4f} s")

    # Validate files are identical to original
    def files_equal(f1, f2):
        with open(f1, 'rb') as a, open(f2, 'rb') as b:
            while True:
                chunk_a = a.read(64*1024)
                chunk_b = b.read(64*1024)
                if chunk_a != chunk_b:
                    return False
                if not chunk_a:
                    break
        return True

    rsa_ok = files_equal(file_path, "decrypted_rsa.bin")
    ecc_ok = files_equal(file_path, "decrypted_ecc.bin")

    print(f"\nRSA decrypted file matches original: {rsa_ok}")
    print(f"ECC decrypted file matches original: {ecc_ok}")

    return {
        "rsa": {
            "keygen_time": rsa_keygen_time,
            "aes_key_enc_time": rsa_enc_key_time,
            "file_enc_time": rsa_file_enc_time,
            "aes_key_dec_time": rsa_dec_key_time,
            "file_dec_time": rsa_file_dec_time,
            "valid": rsa_ok
        },
        "ecc": {
            "keygen_time": ecc_keygen_time,
            "aes_key_enc_time": ecc_enc_key_time,
            "file_enc_time": ecc_file_enc_time,
            "aes_key_dec_time": ecc_dec_key_time,
            "file_dec_time": ecc_file_dec_time,
            "valid": ecc_ok
        }
    }


if __name__ == "__main__":
    # Generate test files for 1MB and 10MB if they don't exist
    for size_mb in [1, 10]:
        filename = f"testfile_{size_mb}MB.bin"
        if not os.path.exists(filename):
            print(f"Generating {size_mb}MB test file...")
            with open(filename, 'wb') as f:
                f.write(os.urandom(size_mb * 1024 * 1024))
        else:
            print(f"{filename} already exists.")

    # Run tests
    results_1mb = run_test("testfile_1MB.bin")
    results_10mb = run_test("testfile_10MB.bin")