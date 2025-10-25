'''
Using DES and AES(128, 192, and 256 bits key).encrypt the five different messages using 
same key. 
a. Consider different modes of operation  
b.  Plot the graph which shows execution time taken by each technique. 
c. Compare time taken by different modes of operation
'''

from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
import time
import matplotlib.pyplot as plt

messages = [b"message1", b"message2", b"message3", b"message4", b"message5"]

key_des = b"8bytekey"                               # 08 bytes
key_aes_128 = b"16bytessssssssss"                   # 16 bytes
key_aes_192 = b"24bytessssssssssssssssss"           # 24 bytes
key_aes_256 = b"32bytessssssssssssssssssssssssss"   # 32 bytes

modes = [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB]
results = {"DES": [], "AES-128": [], "AES-192": [], "AES-256": []}

for mode in modes:
    if mode == AES.MODE_ECB:
        cipher_des = DES.new(key_des, DES.MODE_ECB)
        start = time.time()
        [cipher_des.encrypt(m.ljust(8,b' ')) for m in messages]
        results["DES"].append(time.time()-start)

        cipher_aes = AES.new(key_aes_128, AES.MODE_ECB)
        start = time.time()
        [cipher_aes.encrypt(m.ljust(16,b' ')) for m in messages]
        results["AES-128"].append(time.time()-start)

        cipher_aes = AES.new(key_aes_192, AES.MODE_ECB)
        start = time.time()
        [cipher_aes.encrypt(m.ljust(16,b' ')) for m in messages]
        results["AES-192"].append(time.time()-start)

        cipher_aes = AES.new(key_aes_256, AES.MODE_ECB)
        start = time.time()
        [cipher_aes.encrypt(m.ljust(16,b' ')) for m in messages]
        results["AES-256"].append(time.time()-start)
    else:
        iv = get_random_bytes(8)
        cipher_des = DES.new(key_des, DES.MODE_CBC, iv)
        start = time.time()
        [cipher_des.encrypt(m.ljust(8,b' ')) for m in messages]
        results["DES"].append(time.time()-start)

        iv = get_random_bytes(16)
        cipher_aes = AES.new(key_aes_128, mode, iv)
        start = time.time()
        [cipher_aes.encrypt(m.ljust(16,b' ')) for m in messages]
        results["AES-128"].append(time.time()-start)

        cipher_aes = AES.new(key_aes_192, mode, iv)
        start = time.time()
        [cipher_aes.encrypt(m.ljust(16,b' ')) for m in messages]
        results["AES-192"].append(time.time()-start)

        cipher_aes = AES.new(key_aes_256, mode, iv)
        start = time.time()
        [cipher_aes.encrypt(m.ljust(16,b' ')) for m in messages]
        results["AES-256"].append(time.time()-start)

labels = ["ECB", "CBC", "CFB"]
plt.plot(labels, results["DES"], label="DES")
plt.plot(labels, results["AES-128"], label="AES-128")
plt.plot(labels, results["AES-192"], label="AES-192")
plt.plot(labels, results["AES-256"], label="AES-256")
plt.xlabel("Mode")
plt.ylabel("Execution Time (s)")
plt.title("DES vs AES Execution Time by Mode")
plt.legend()
plt.show()
