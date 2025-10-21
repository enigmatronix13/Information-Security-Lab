# Additive Cipher

def additive_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").lower()
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            ciphertext += chr((ord(char) - 97 + key) % 26 + 97)
    return ciphertext

def additive_decrypt(ciphertext, key):
    plaintext = ''
    for char in ciphertext:
        if char.isalpha():
            plaintext += chr((ord(char) - 97 - key) % 26 + 97)
    return plaintext

message = "I am learning information security"
key = 20

cipher = additive_encrypt(message, key)
print("Encrypted:", cipher)

original = additive_decrypt(cipher, key)
print("Decrypted:", original)