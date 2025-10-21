# Hill Cipher

import numpy as np

def hill_encrypt(plaintext, key_matrix):
    plaintext = plaintext.replace(" ", "").upper()
    if len(plaintext) % 2 != 0:
        plaintext += 'X' 

    def letter_to_num(c):
        return ord(c) - ord('A')

    def num_to_letter(n):
        return chr(n + ord('A'))

    pairs = [plaintext[i:i+2] for i in range(0, len(plaintext), 2)]
    ciphertext = ""

    for pair in pairs:
        vector = np.array([[letter_to_num(pair[0])],
                           [letter_to_num(pair[1])]])

        result = np.dot(key_matrix, vector) % 26
 
        ciphertext += num_to_letter(result[0][0])
        ciphertext += num_to_letter(result[1][0])

    return ciphertext

key_matrix = np.array([[3, 3],
                       [2, 7]])

plaintext = "We live in an insecure world"
ciphertext = hill_encrypt(plaintext, key_matrix)
print("Encrypted text:", ciphertext)