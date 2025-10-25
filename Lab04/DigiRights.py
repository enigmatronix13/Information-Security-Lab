'''
DigiRights Inc. is a leading provider of digital content, including e-books, movies, and music. 
The company has implemented a secure digital rights management (DRM) system using the 
ElGamal cryptosystem to protect its valuable digital assets. Implement a Python-based 
centralized key management and access control service that can:   
• Key Generation: Generate a master public-private key pair using the ElGamal 
cryptosystem. The key size should be configurable (e.g., 2048 bits).   
• Content Encryption: Provide an API for content creators to upload their digital content and 
have it encrypted using the master public key.   
• Key Distribution: Manage the distribution of the master private key to authorized 
customers, allowing them to decrypt the content.   
• Access Control: Implement flexible access control mechanisms, such as:   
o Granting limited-time access to customers for specific content   
o Revoking access to customers for specific content   
o Allowing content creators to manage access to their own content   
• Key Revocation: Implement a process to revoke the master private key in case of a security 
breach or other emergency.     
• Key Renewal: Automatically renew the master public-private key pair at regular intervals 
(e.g., every 24 months) to maintain the security of the DRM system. 
• Secure Storage: Securely store the master private key, ensuring that it is not accessible to 
unauthorized parties.   
• Auditing and Logging: Maintain detailed logs of all key management and access control 
operations to enable auditing and troubleshooting.    
'''
import os, json, base64
from datetime import datetime, timedelta
from typing import Dict, Optional
from Crypto.Util import number
from Crypto.Random import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa

# --- small helpers ---
def now_iso(): return datetime.utcnow().isoformat()
def b64(b: bytes) -> str: return base64.b64encode(b).decode()
def ub64(s: str) -> bytes: return base64.b64decode(s)

def derive_key(passphrase: bytes, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=200_000)
    return kdf.derive(passphrase)

# --- ElGamal (integer-based, compact) ---
class ElGamalMaster:
    def __init__(self, bits: int = 2048):
        self.p = number.getPrime(bits)
        self.g = 2
        self.x = random.StrongRandom().randint(2, self.p - 2)
        self.y = pow(self.g, self.x, self.p)

    def public(self):
        return (self.p, self.g, self.y)

    def encrypt_int(self, m: int):
        r = random.StrongRandom().randint(2, self.p - 2)
        a = pow(self.g, r, self.p)
        b = (m * pow(self.y, r, self.p)) % self.p
        return a, b

    def decrypt_int(self, a: int, b: int):
        s = pow(a, self.x, self.p)
        s_inv = number.inverse(s, self.p)
        return (b * s_inv) % self.p

    def export_private(self) -> bytes:
        return json.dumps({'p': str(self.p), 'g': str(self.g), 'x': str(self.x), 'y': str(self.y)}).encode()

    @staticmethod
    def import_private(blob: bytes):
        j = json.loads(blob.decode())
        obj = ElGamalMaster.__new__(ElGamalMaster)
        obj.p, obj.g, obj.x, obj.y = int(j['p']), int(j['g']), int(j['x']), int(j['y'])
        return obj

# --- DigiRights manager ---
class DigiRightsManager:
    def __init__(self, master_passphrase: bytes, master_bits: int = 2048):
        self.master_enc = None
        self.master_salt = None
        self.master_created = None
        self.master: Optional[ElGamalMaster] = None
        self.contents: Dict[str, dict] = {}     # content_id -> {cipher, wrap_a, wrap_b, created}
        self.acl: Dict[str, Dict[str, dict]] = {}   # content_id -> {customer_id: {expires, enc_key}}
        self.customers: Dict[str, bytes] = {}   # customer_id -> RSA public key PEM
        self.logs = []
        self._create_and_store_master(master_passphrase, bits=master_bits)

    def _log(self, msg: str):
        self.logs.append({'ts': now_iso(), 'msg': msg})

    def _create_and_store_master(self, passphrase: bytes, bits: int = 2048):
        self.master = ElGamalMaster(bits=bits)
        blob = self.master.export_private()
        salt = os.urandom(16)
        key = derive_key(passphrase, salt)
        aesg = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesg.encrypt(nonce, blob, None)
        self.master_enc = b64(nonce + ct)
        self.master_salt = b64(salt)
        self.master_created = now_iso()
        self._log("Master key generated and stored")

    def load_master(self, passphrase: bytes) -> bool:
        try:
            salt = ub64(self.master_salt)
            key = derive_key(passphrase, salt)
            data = ub64(self.master_enc)
            nonce, ct = data[:12], data[12:]
            blob = AESGCM(key).decrypt(nonce, ct, None)
            self.master = ElGamalMaster.import_private(blob)
            self._log("Master key loaded into memory")
            return True
        except Exception as e:
            self._log(f"Failed to load master key: {e}")
            return False

    def revoke_master(self, passphrase: bytes):
        old_master = self.master
        self._create_and_store_master(passphrase)
        # rewrap content symmetric keys with new master
        for cid, meta in self.contents.items():
            a_old, b_old = int(meta['wrap_a']), int(meta['wrap_b'])
            k_int = old_master.decrypt_int(a_old, b_old)
            a_new, b_new = self.master.encrypt_int(k_int)
            meta['wrap_a'], meta['wrap_b'] = str(a_new), str(b_new)
        self._log("Master key revoked and rotated")

    def register_customer(self, customer_id: str, rsa_public_pem: bytes):
        self.customers[customer_id] = rsa_public_pem
        self._log(f"Customer registered: {customer_id}")

    def upload_content(self, content_id: str, plaintext: bytes):
        # sym key + AES-GCM content encryption
        sym = AESGCM.generate_key(bit_length=256)
        aesg = AESGCM(sym)
        nonce = os.urandom(12)
        ct = aesg.encrypt(nonce, plaintext, None)
        # wrap sym key with ElGamal
        k_int = int.from_bytes(sym, 'big')
        a, b = self.master.encrypt_int(k_int)
        self.contents[content_id] = {'cipher': b64(nonce + ct), 'wrap_a': str(a), 'wrap_b': str(b), 'created': now_iso()}
        self.acl[content_id] = {}
        self._log(f"Content uploaded: {content_id}")

    def grant_access(self, content_id: str, customer_id: str, duration_hours: int = 24):
        if customer_id not in self.customers:
            raise ValueError("Unknown customer")
        if content_id not in self.contents:
            raise ValueError("Unknown content")
        a, b = int(self.contents[content_id]['wrap_a']), int(self.contents[content_id]['wrap_b'])
        k_int = self.master.decrypt_int(a, b)
        sym = int.to_bytes(k_int, (k_int.bit_length() + 7) // 8 or 1, 'big')
        pub = serialization.load_pem_public_key(self.customers[customer_id])
        enc = pub.encrypt(sym, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        expiry = (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat()
        self.acl[content_id][customer_id] = {'expires': expiry, 'enc_key': b64(enc)}
        self._log(f"Access granted: {content_id} -> {customer_id} until {expiry}")

    def revoke_access(self, content_id: str, customer_id: str, rotate_key: bool = True):
        if content_id in self.acl and customer_id in self.acl[content_id]:
            del self.acl[content_id][customer_id]
            self._log(f"Access revoked: {content_id} -> {customer_id}")
            if rotate_key:
                # rotate symmetric key and re-encrypt content and ACL entries
                old_a, old_b = int(self.contents[content_id]['wrap_a']), int(self.contents[content_id]['wrap_b'])
                old_k_int = self.master.decrypt_int(old_a, old_b)
                old_sym = int.to_bytes(old_k_int, (old_k_int.bit_length() + 7) // 8 or 1, 'big')
                nonce_ct = ub64(self.contents[content_id]['cipher'])
                nonce, ct = nonce_ct[:12], nonce_ct[12:]
                plain = AESGCM(old_sym).decrypt(nonce, ct, None)
                new_sym = AESGCM.generate_key(bit_length=256)
                new_nonce = os.urandom(12)
                new_ct = AESGCM(new_sym).encrypt(new_nonce, plain, None)
                new_k_int = int.from_bytes(new_sym, 'big')
                a_new, b_new = self.master.encrypt_int(new_k_int)
                self.contents[content_id]['cipher'] = b64(new_nonce + new_ct)
                self.contents[content_id]['wrap_a'] = str(a_new); self.contents[content_id]['wrap_b'] = str(b_new)
                # re-wrap for remaining ACL customers
                for cust in list(self.acl[content_id].keys()):
                    pub = serialization.load_pem_public_key(self.customers[cust])
                    enc_for_cust = pub.encrypt(new_sym, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                    self.acl[content_id][cust]['enc_key'] = b64(enc_for_cust)
                self._log(f"Content key rotated for {content_id}")

    def get_package_for_customer(self, content_id: str, customer_id: str) -> Optional[dict]:
        if content_id not in self.contents:
            return None
        entry = self.acl.get(content_id, {}).get(customer_id)
        if not entry:
            return None
        if datetime.fromisoformat(entry['expires']) < datetime.utcnow():
            del self.acl[content_id][customer_id]
            self._log(f"Access expired: {content_id} -> {customer_id}")
            return None
        return {'cipher': self.contents[content_id]['cipher'], 'enc_key': entry['enc_key']}

    def dump_logs(self) -> str:
        return json.dumps(self.logs, indent=2)

# --- compact demo ---
def demo():
    mgr = DigiRightsManager(master_passphrase=b"demo-pass")
    mgr.load_master(b"demo-pass")

    # create a customer
    cust_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cust_pub_pem = cust_priv.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)
    mgr.register_customer("alice", cust_pub_pem)

    mgr.upload_content("ebook-001", b"Very secret ebook")
    mgr.grant_access("ebook-001", "alice", duration_hours=2)

    pkg = mgr.get_package_for_customer("ebook-001", "alice")
    if pkg:
        enc_key = ub64(pkg['enc_key'])
        sym = cust_priv.decrypt(enc_key, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        cipher_blob = ub64(pkg['cipher'])
        nonce, ct = cipher_blob[:12], cipher_blob[12:]
        plain = AESGCM(sym).decrypt(nonce, ct, None)
        print("Alice recovered:", plain.decode())

    print("Audit log:", mgr.dump_logs()[:400])

if __name__ == "__main__":
    demo()