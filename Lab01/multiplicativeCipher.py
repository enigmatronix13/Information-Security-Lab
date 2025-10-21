# Multiplicative Cipher

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise Exception("Multiplicative inverse doesn't exist")

def multiplicative_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").lower()
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            ciphertext += chr((ord(char) - 97) * key % 26 + 97)
    return ciphertext

def multiplicative_decrypt(ciphertext, key):
    inv_key = modinv(key, 26)
    plaintext = ''
    for char in ciphertext:
        if char.isalpha():
            plaintext += chr((ord(char) - 97) * inv_key % 26 + 97)
    return plaintext

message = "I am learning information security"
key = 15

cipher = multiplicative_encrypt(message, key)
print("Encrypted:", cipher)

original = multiplicative_decrypt(cipher, key)
print("Decrypted:", original)