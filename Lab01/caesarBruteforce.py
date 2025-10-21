# Caesar Cipher Decryption Using Known Plaintext

def caesar_decrypt(ciphertext, shift):
    result = ""
    for char in ciphertext:
        if char.isalpha():
            result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
    return result.lower()

print(caesar_decrypt("XVIEWYWI", 4)) 