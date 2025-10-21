import os, statistics
from time import perf_counter
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

message = b"Performance Testing of Encryption Algorithms"

# --- DES test ---
def test_des(message):
    key = os.urandom(8)  # 64-bit key
    cipher = DES.new(key, DES.MODE_CBC)
    start_enc = perf_counter()
    ct = cipher.encrypt(pad(message, 8))
    end_enc = perf_counter()

    cipher2 = DES.new(key, DES.MODE_CBC, iv=cipher.iv)
    start_dec = perf_counter()
    dec = unpad(cipher2.decrypt(ct), 8)
    end_dec = perf_counter()
    return (end_enc - start_enc), (end_dec - start_dec), dec

# --- AES-256 test ---
def test_aes256(message):
    key = os.urandom(32)  # 256-bit key
    cipher = AES.new(key, AES.MODE_CBC)
    start_enc = perf_counter()
    ct = cipher.encrypt(pad(message, 16))
    end_enc = perf_counter()

    cipher2 = AES.new(key, AES.MODE_CBC, iv=cipher.iv)
    start_dec = perf_counter()
    dec = unpad(cipher2.decrypt(ct), 16)
    end_dec = perf_counter()
    return (end_enc - start_enc), (end_dec - start_dec), dec

# --- Benchmark ---
def benchmark(func, runs=10000):
    enc_times, dec_times = [], []
    for _ in range(runs):
        enc, dec, msg2 = func(message)
        assert msg2 == message
        enc_times.append(enc)
        dec_times.append(dec)
    return statistics.mean(enc_times), statistics.mean(dec_times)

des_enc, des_dec = benchmark(test_des)
aes_enc, aes_dec = benchmark(test_aes256)

print(f"DES Encryption Avg: {des_enc*1e6:.2f} µs")
print(f"DES Decryption Avg: {des_dec*1e6:.2f} µs")
print(f"AES-256 Encryption Avg: {aes_enc*1e6:.2f} µs")
print(f"AES-256 Decryption Avg: {aes_dec*1e6:.2f} µs")