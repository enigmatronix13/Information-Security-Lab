'''
Execute the following for SSE: 
1a. Create a dataset: Generate a text corpus of at least ten documents. Each document 
should contain multiple words. 
1b. Implement encryption and decryption functions: Use the AES encryption and 
decryption functions. 
1c. Create an inverted index: Build an inverted index mapping word to the list of 
document IDs containing those words. 
o Encrypt the index using the provided encryption function. 
1d. Implement the search function: 
o Take a search query as input. 
o Encrypt the query. 
o Search the encrypted index for matching terms. 
o Decrypt the returned document IDs and display the corresponding documents
'''


import json
import re
import base64
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16

def pkcs7_pad(b: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(b) % BLOCK_SIZE)
    return b + bytes([pad_len]) * pad_len

def pkcs7_unpad(b: bytes) -> bytes:
    pad_len = b[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return b[:-pad_len]

def aes_encrypt(key: bytes, plaintext_bytes: bytes) -> str:
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext_bytes))
    return base64.b64encode(iv + ct).decode()

def aes_decrypt(key: bytes, b64_iv_ct: str) -> bytes:
    raw = base64.b64decode(b64_iv_ct)
    iv = raw[:BLOCK_SIZE]
    ct = raw[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    return pkcs7_unpad(pt_padded)

def make_token(master_key: bytes, term: str) -> str:
    return hmac.new(master_key, term.encode('utf-8'), hashlib.sha256).hexdigest()

corpus = {
    1: "Apple and banana smoothie recipe with fresh mint.",
    2: "Distributed systems: design and implementation notes.",
    3: "Banana bread recipe: moist, simple and fluffy.",
    4: "Introduction to cryptography and symmetric encryption.",
    5: "How to build a web server in Python using sockets.",
    6: "Guide to machine learning: supervised and unsupervised methods.",
    7: "Apple pie instructions: crust tips and baking temperature.",
    8: "DevOps: Docker, Kubernetes, and continuous delivery.",
    9: "Networking basics: TCP, UDP, and sockets explained.",
    10: "Data structures and algorithms: arrays, lists, and trees.",
    11: "Healthy smoothies: spinach, apple, banana and nuts.",
}

def tokenize(text: str):
    text = text.lower()
    tokens = re.findall(r"[a-z0-9]+", text)
    return tokens

inverted = {}
for doc_id, text in corpus.items():
    for term in set(tokenize(text)):
        inverted.setdefault(term, set()).add(doc_id)
inverted = {t: sorted(list(ds)) for t, ds in inverted.items()}

MASTER_KEY = hashlib.sha256(b"super secret master key for hmac").digest()
AES_KEY = hashlib.sha256(b"another secret key for aes encryption").digest()[:32]

encrypted_index = {}
for term, posting_list in inverted.items():
    token = make_token(MASTER_KEY, term)
    posting_json = json.dumps(posting_list).encode('utf-8')
    encrypted_postings = aes_encrypt(AES_KEY, posting_json)
    encrypted_index[token] = encrypted_postings

def sse_search(query: str):
    tokens = tokenize(query)
    if not tokens:
        return []
    result_ids = set()
    for term in tokens:
        token = make_token(MASTER_KEY, term)
        enc_postings = encrypted_index.get(token)
        if not enc_postings:
            continue
        try:
            dec_bytes = aes_decrypt(AES_KEY, enc_postings)
            posting_list = json.loads(dec_bytes.decode('utf-8'))
            result_ids.update(posting_list)
        except Exception:
            pass
    results = [(doc_id, corpus[doc_id]) for doc_id in sorted(result_ids)]
    return results

if __name__ == "__main__":
    print("Corpus documents (id: first 60 chars):")
    for i, txt in corpus.items():
        print(f"{i}: {txt[:60]}")
    print("\n--- Inverted index (plaintext) sample ---")
    sample_terms = ["apple", "banana", "sockets", "docker"]
    for t in sample_terms:
        print(t, "->", inverted.get(t, []))
    queries = [
        "apple",
        "banana",
        "sockets",
        "machine learning",
        "docker kubernetes",
        "salmon"
    ]
    for q in queries:
        print("\nSearch query:", q)
        res = sse_search(q)
        if not res:
            print("  No results.")
        else:
            for doc_id, text in res:
                print(f"  Doc {doc_id}: {text}")