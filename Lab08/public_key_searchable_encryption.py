'''
Execute the following for PKSE:   
2a. Create a dataset:   
o Generate a text corpus of at least ten documents. Each document should contain 
multiple words.   
2b. Implement encryption and decryption functions:   
o Use the Paillier cryptosystem for encryption and decryption.   
2c. Create an encrypted index:   
o Build an inverted index mapping word to the list of document IDs containing 
those words.   
o Encrypt the index using the Paillier cryptosystem.   
2d. Implement the search function:   
o Take a search query as input.   
o Encrypt the query using the public key.   
o Search the encrypted index for matching terms.   
o Decrypt the returned document IDs using the private key.  
'''

import json, re, secrets, hashlib
from math import gcd

def is_prime(n, k=8):
    if n < 2: return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0: return n == p
    r, d = 0, n-1
    while d % 2 == 0: r+=1; d//=2
    for _ in range(k):
        a = secrets.randbelow(n-3)+2
        x = pow(a,d,n)
        if x==1 or x==n-1: continue
        composite=True
        for _ in range(r-1):
            x=pow(x,2,n)
            if x==n-1: composite=False; break
        if composite: return False
    return True

def get_prime(bits=512):
    while True:
        p = secrets.randbits(bits) | (1<<(bits-1)) | 1
        if is_prime(p): return p

def lcm(a,b): return a//gcd(a,b)*b

def paillier_keygen(bits=1024):
    p,q=get_prime(bits//2),get_prime(bits//2)
    n=p*q; nsq=n*n; lam=lcm(p-1,q-1); g=n+1
    def L(u): return (u-1)//n
    mu = pow(L(pow(g,lam,nsq)),-1,n)
    return {'pub':(n,g),'priv':(lam,mu)}

def paillier_encrypt(pub,m):
    n,g=pub; nsq=n*n
    m_int=int.from_bytes(m,'big') if isinstance(m,bytes) else m
    if m_int>=n: raise ValueError("message too large")
    r=secrets.randbelow(n-1)+1
    return (pow(g,m_int,nsq)*pow(r,n,nsq))%nsq

def paillier_decrypt(keys,c):
    n=keys['pub'][0]; nsq=n*n; lam,mu=keys['priv']
    def L(u): return (u-1)//n
    m_int=(L(pow(c,lam,nsq))*mu)%n
    return m_int

corpus={
1:"Apple and banana smoothie recipe with fresh mint.",
2:"Distributed systems design and implementation notes.",
3:"Banana bread recipe moist simple and fluffy.",
4:"Introduction to cryptography and symmetric encryption.",
5:"How to build a web server in Python using sockets.",
6:"Guide to machine learning supervised and unsupervised methods.",
7:"Apple pie instructions crust tips and baking temperature.",
8:"DevOps Docker Kubernetes and continuous delivery.",
9:"Networking basics TCP UDP and sockets explained.",
10:"Data structures and algorithms arrays lists and trees.",
11:"Healthy smoothies spinach apple banana and nuts."
}

def tokenize(text): return re.findall(r"[a-z0-9]+", text.lower())

inverted={}
for doc_id,text in corpus.items():
    for term in set(tokenize(text)):
        inverted.setdefault(term,set()).add(doc_id)
inverted={t:sorted(list(ds)) for t,ds in inverted.items()}

master_hmac = hashlib.sha256(b"pkse hmac master").digest()
def make_token(term): return hashlib.sha256(master_hmac+term.encode()).hexdigest()

keys=paillier_keygen(1024)
pub=keys['pub']

encrypted_index={}
for term,posting in inverted.items():
    token=make_token(term)
    posting_json=json.dumps(posting).encode()
    c=paillier_encrypt(pub,posting_json)
    encrypted_index[token]=c

def pkse_encrypt_query(query):
    tokens=tokenize(query)
    enc_query_list=[]
    for term in tokens:
        token=make_token(term)
        token_bytes=term.encode()
        enc=paillier_encrypt(pub,token_bytes)
        enc_query_list.append((term,token,enc))
    return enc_query_list

def pkse_search(query):
    tokens=tokenize(query)
    result_ids=set()
    for term in tokens:
        token=make_token(term)
        c=encrypted_index.get(token)
        if c is None: continue
        m_int=paillier_decrypt(keys,c)
        b=m_int.to_bytes((m_int.bit_length()+7)//8,'big') if m_int!=0 else b'\x00'
        posting=json.loads(b.decode())
        result_ids.update(posting)
    return [(doc_id,corpus[doc_id]) for doc_id in sorted(result_ids)]

if __name__=="__main__":
    print("Encrypted index entries:",len(encrypted_index))
    queries=["apple","banana","sockets","machine learning","docker kubernetes","salmon"]
    for q in queries:
        enc_q=pkse_encrypt_query(q)
        print(f"\nQuery: {q}")
        print("Encrypted tokens (sample):",[(t[0],hex(t[2])[:10]) for t in enc_q])
        res=pkse_search(q)
        if not res: print(" No results.")
        else:
            for doc_id,text in res: print(f" Doc {doc_id}: {text}")
