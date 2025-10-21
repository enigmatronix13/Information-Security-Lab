# Playfair Cipher

import string

def create_matrix(key):
    key = key.upper().replace("J", "I")
    unique = []
    for char in key + string.ascii_uppercase:
        if char not in unique and char != 'J':
            unique.append(char)
    return [unique[i:i+5] for i in range(0, 25, 5)]

def prepare_text(text):
    text = text.upper().replace("J", "I").replace(" ", "")
    result = ""
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            result += a + 'X'
            i += 1
        else:
            result += a + b
            i += 2
    if len(result) % 2 != 0:
        result += 'X'
    return result

def find(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c

def encrypt(text, matrix):
    text = prepare_text(text)
    cipher = ""
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        r1, c1 = find(matrix, a)
        r2, c2 = find(matrix, b)
        if r1 == r2:
            cipher += matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]
        elif c1 == c2:
            cipher += matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]
        else:
            cipher += matrix[r1][c2] + matrix[r2][c1]
    return cipher

def decrypt(cipher, matrix):
    plain = ""
    for i in range(0, len(cipher), 2):
        a, b = cipher[i], cipher[i+1]
        r1, c1 = find(matrix, a)
        r2, c2 = find(matrix, b)
        if r1 == r2:
            plain += matrix[r1][(c1-1)%5] + matrix[r2][(c2-1)%5]
        elif c1 == c2:
            plain += matrix[(r1-1)%5][c1] + matrix[(r2-1)%5][c2]
        else:
            plain += matrix[r1][c2] + matrix[r2][c1]
    return plain

key = "GUIDANCE"
msg = "The key is hidden under the door pad"

matrix = create_matrix(key)
cipher = encrypt(msg, matrix)
decrypted = decrypt(cipher, matrix)

print("Playfair Matrix:")
[print(" ".join(row)) for row in matrix]
print("\nEncrypted:", cipher)
print("Decrypted:", decrypted)