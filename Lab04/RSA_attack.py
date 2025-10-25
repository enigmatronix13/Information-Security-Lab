'''   
Suppose that XYZ Logistics has decided to use the RSA cryptosystem to secure their sensitive 
communications. However, the security team at XYZ Logistics has discovered that one of their 
employees, Eve, has obtained a partial copy of the RSA private key and is attempting to 
recover the full private key to decrypt the company's communications.   
Eve's attack involves exploiting a vulnerability in the RSA key generation process, where the 
prime factors (p and q) used to generate the modulus (n) are not sufficiently large or random. 
Develop a Python script that can demonstrate the attack on the vulnerable RSA cryptosystem  
and discuss the steps to mitigate the attack.  
'''
import random, math
from typing import Tuple

# --- small utilities ---
def is_probable_prime(n: int, k: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # Miller-Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2; s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits: int) -> int:
    while True:
        p = random.getrandbits(bits) | 1 | (1 << (bits - 1))
        if is_probable_prime(p):
            return p

def egcd(a: int, b: int) -> Tuple[int,int,int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

# --- Pollard's Rho (suitable for demo / weak keys) ---
def pollards_rho(n: int) -> int:
    if n % 2 == 0:
        return 2
    for attempt in range(5):
        x = random.randrange(2, n - 1)
        y = x
        c = random.randrange(1, n - 1)
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            if d == n:
                break
        if d > 1 and d < n:
            return d
    return None

def factor(n: int) -> Tuple[int,int]:
    # Try trivial trial division first
    for p in [2,3,5,7,11,13,17,19,23,29,31,37,41]:
        if n % p == 0:
            return p, n//p
    # Pollard's Rho
    f = pollards_rho(n)
    if f and f != 1 and f != n:
        return int(f), int(n // f)
    raise ValueError("Factorization failed (n likely not weak)")

# --- RSA helper functions ---
def generate_weak_rsa(bits: int = 64, e: int = 65537):
    # small primes for vulnerability demo
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    while q == p:
        q = gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        return generate_weak_rsa(bits, e)  # try again
    d = modinv(e, phi)
    return {'p': p, 'q': q, 'n': n, 'e': e, 'd': d}

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def int_to_bytes(i: int) -> bytes:
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder='big')

# --- Demonstration: Eve attempting to recover private key ---
def demo_attack():
    print("=== RSA Factorization Attack Demo (weak keys) ===")
    rsa = generate_weak_rsa(bits=64)  # deliberately small for demo
    n, e = rsa['n'], rsa['e']
    d_true = rsa['d']
    print(f"Public key (n): {n}")
    print(f"Public exponent (e): {e}\n")

    # Encrypt a short message (ensure it fits)
    msg = b"Secret"
    m_int = int_from_bytes(msg)
    if m_int >= n:
        raise RuntimeError("Message too large for chosen modulus in demo")
    c = pow(m_int, e, n)
    print(f"Ciphertext (int): {c}\n")

    # Eve tries to factor n
    try:
        p, q = factor(n)
        if p > q:
            p, q = q, p
        print(f"Eve found factors p={p}, q={q}")
    except Exception as exc:
        print("Eve failed to factor n:", exc)
        return

    # Recompute private exponent
    phi = (p - 1) * (q - 1)
    d_recovered = modinv(e, phi)
    print(f"Recovered d: {d_recovered}")
    print(f"Original d:  {d_true}\n")

    # Decrypt using recovered d
    m_rec = pow(c, d_recovered, n)
    plaintext = int_to_bytes(m_rec)
    print("Recovered plaintext:", plaintext.decode())

    # Summary & mitigations
    print("\nMitigations:")
    print("- Use strong prime sizes (2048+ bit modulus).")
    print("- Use secure RNGs and vetted libraries for key generation.")
    print("- Avoid predictable/small primes and reuse of primes.")
    print("- Monitor for signs of weak key material and rotate keys promptly.")

if __name__ == "__main__":
    demo_attack()

