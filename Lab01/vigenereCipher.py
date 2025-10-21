# Vigenère Cipher

def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").lower()
    key = key.lower()
    ciphertext = ''
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 97
            ciphertext += chr((ord(char) - 97 + shift) % 26 + 97)
            key_index += 1
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    plaintext = ''
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 97
            plaintext += chr((ord(char) - 97 - shift) % 26 + 97)
            key_index += 1
    return plaintext

message = "the house is being sold tonight"
key = "dollars"

cipher = vigenere_encrypt(message, key)
print("Encrypted:", cipher)

original = vigenere_decrypt(cipher, key)
print("Decrypted:", original)