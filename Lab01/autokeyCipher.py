# Autokey Cipher

def autokey_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").lower()
    full_key = [key] + [ord(c) - 97 for c in plaintext[:-1]]
    ciphertext = ''

    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = full_key[i]
            ciphertext += chr((ord(char) - 97 + shift) % 26 + 97)
    return ciphertext

def autokey_decrypt(ciphertext, key):
    ciphertext = ciphertext.lower()
    plaintext = ''
    current_key = [key]

    for i, char in enumerate(ciphertext):
        shift = current_key[i]
        p_char = chr((ord(char) - 97 - shift) % 26 + 97)
        plaintext += p_char
        current_key.append(ord(p_char) - 97)
    return plaintext

message = "the house is being sold tonight"
key = 7

cipher = autokey_encrypt(message, key)
print("Encrypted:", cipher)

original = autokey_decrypt(cipher, key)
print("Decrypted:", original)