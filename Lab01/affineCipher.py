# Affine Cipher

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise Exception("No modular inverse")

def affine_encrypt(plaintext, a, b):
    plaintext = plaintext.replace(" ", "").lower()
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            ciphertext += chr(((ord(char) - 97) * a + b) % 26 + 97)
    return ciphertext

def affine_decrypt(ciphertext, a, b):
    inv_a = modinv(a, 26)
    plaintext = ''
    for char in ciphertext:
        if char.isalpha():
            plaintext += chr((inv_a * ((ord(char) - 97) - b)) % 26 + 97)
    return plaintext

message = "I am learning information security"
a, b = 15, 20

cipher = affine_encrypt(message, a, b)
print("Encrypted:", cipher)

original = affine_decrypt(cipher, a, b)
print("Decrypted:", original)