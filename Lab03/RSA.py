from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

def generate_rsa_keys(bits=512):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537 

    d = inverse(e, phi)
    return (n, e), (n, d)

def rsa_encrypt(message, pubkey):
    n, e = pubkey
    msg_int = bytes_to_long(message.encode('utf-8'))
    cipher_int = pow(msg_int, e, n)
    return cipher_int

def rsa_decrypt(cipher_int, privkey):
    n, d = privkey
    decrypted_int = pow(cipher_int, d, n)
    decrypted_msg = long_to_bytes(decrypted_int).decode('utf-8')
    return decrypted_msg

if __name__ == "__main__":
    message = "Asymmetric Encryption"

    public_key, private_key = generate_rsa_keys()

    print(f"Public key (n, e): {public_key}")
    print(f"Private key (n, d): {private_key}")

    ciphertext = rsa_encrypt(message, public_key)
    print(f"Ciphertext: {ciphertext}")

    decrypted_message = rsa_decrypt(ciphertext, private_key)
    print(f"Decrypted message: {decrypted_message}")