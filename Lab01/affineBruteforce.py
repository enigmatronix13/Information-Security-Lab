def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_encrypt(text, a, b):
    result = ''
    for char in text.lower():
        if char.isalpha():
            x = ord(char) - ord('a')
            result += chr((a * x + b) % 26 + ord('A'))
        else:
            result += char
    return result

def affine_decrypt(cipher, a, b):
    a_inv = modinv(a, 26)
    if a_inv is None:
        return None
    result = ''
    for char in cipher.upper():
        if char.isalpha():
            y = ord(char) - ord('A')
            result += chr((a_inv * (y - b)) % 26 + ord('A'))
        else:
            result += char
    return result

ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
plaintext_sample = "ab"
cipher_sample = "GL"

valid_a = [a for a in range(1, 26) if modinv(a, 26) is not None]

found = False
for a in valid_a:
    for b in range(26):
        trial = affine_encrypt(plaintext_sample, a, b)
        if trial == cipher_sample:
            print(f"Found key: a={a}, b={b}")
            decrypted = affine_decrypt(ciphertext, a, b)
            print("Decrypted Message:", decrypted)
            found = True
            break
    if found:
        break
