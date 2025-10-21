from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate ECC key pair
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt message using recipient's public key
def ecc_encrypt(public_key, plaintext):
    # Generate ephemeral key
    ephemeral_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Derive shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive symmetric key from shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)

    # Encrypt the plaintext with AES-GCM
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    # Return ephemeral public key + iv + ciphertext + tag
    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    return ephemeral_pub_bytes, iv, ciphertext, encryptor.tag

# Decrypt message using recipient's private key
def ecc_decrypt(private_key, ephemeral_pub_bytes, iv, ciphertext, tag):
    # Load ephemeral public key from bytes
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP384R1(), ephemeral_pub_bytes
    )

    # Derive shared secret
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive symmetric key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)

    # Decrypt ciphertext
    decryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

if __name__ == "__main__":
    message = "Secure Transactions"

    # Generate keys
    priv_key, pub_key = generate_keys()
    print("Keys generated.")

    # Encrypt
    eph_pub, iv, ct, tag = ecc_encrypt(pub_key, message)
    print("Message encrypted.")

    # Decrypt
    decrypted = ecc_decrypt(priv_key, eph_pub, iv, ct, tag)
    print("Decrypted message:", decrypted)