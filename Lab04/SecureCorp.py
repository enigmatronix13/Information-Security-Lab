from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, json, base64
from datetime import datetime
from typing import Optional


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n]) * n

def pkcs7_unpad(data: bytes) -> bytes:
    n = data[-1]
    if n < 1 or n > len(data):
        raise ValueError("Invalid padding")
    return data[:-n]


# --- Compact KeyManager ---
class KeyManager:
    def __init__(self):
        self.rsa = {}        # system_id -> private key
        self.dh_priv = {}    # system_id -> DH private key
        self.dh_pub = {}     # system_id -> DH public key
        self.sessions = {}   # (a,b) -> session_key bytes
        self.revoked = set()
        self._dh_params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

    def create_keys(self, system_id: str):
        # RSA
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.rsa[system_id] = priv
        # DH
        dpriv = self._dh_params.generate_private_key()
        self.dh_priv[system_id] = dpriv
        self.dh_pub[system_id] = dpriv.public_key()

    def revoke(self, system_id: str):
        self.revoked.add(system_id)
        self.rsa.pop(system_id, None)
        self.dh_priv.pop(system_id, None)
        self.dh_pub.pop(system_id, None)
        # remove session keys involving system_id
        for k in list(self.sessions):
            if system_id in k:
                self.sessions.pop(k, None)

    def is_valid(self, system_id: str) -> bool:
        return system_id not in self.revoked and system_id in self.rsa

    def get_session(self, a: str, b: str) -> Optional[bytes]:
        return self.sessions.get((a, b))

    def establish_session(self, a: str, b: str) -> bytes:
        if not (a in self.dh_priv and b in self.dh_pub):
            raise RuntimeError("DH keys missing for participants")
        s1 = self.dh_priv[a].exchange(self.dh_pub[b])
        # derive 32-byte AES key
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"session", backend=default_backend()).derive(s1)
        self.sessions[(a, b)] = key
        self.sessions[(b, a)] = key
        return key


# --- Document and Subsystem ---
class Document:
    def __init__(self, content: str, dtype: str, doc_id: str):
        self.content = content
        self.type = dtype
        self.id = doc_id
        self.ts = datetime.utcnow().isoformat()
        self.signature = None
        self.sender = None

    def to_json(self):
        return json.dumps({'content': self.content, 'type': self.type, 'id': self.id, 'ts': self.ts, 'sender': self.sender})


class Subsystem:
    def __init__(self, sid: str, name: str, km: KeyManager):
        self.id = sid
        self.name = name
        self.km = km
        km.create_keys(sid)
        self.inbox = []

    def sign(self, doc: Document) -> bytes:
        if not self.km.is_valid(self.id):
            raise RuntimeError("Signing key not available")
        doc.sender = self.id
        priv = self.km.rsa[self.id]
        sig = priv.sign(doc.to_json().encode(),
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256())
        doc.signature = base64.b64encode(sig).decode()
        return sig

    def verify(self, doc: Document, sender_id: str) -> bool:
        if not self.km.is_valid(sender_id):
            return False
        pub = self.km.rsa[sender_id].public_key()
        try:
            sig = base64.b64decode(doc.signature)
            pub.verify(sig, doc.to_json().encode(),
                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                       hashes.SHA256())
            return True
        except Exception:
            return False

    def encrypt(self, doc: Document, recipient_id: str) -> dict:
        if not self.km.is_valid(self.id):
            raise RuntimeError("Sender key invalid")
        # session key
        key = self.km.get_session(self.id, recipient_id) or self.km.establish_session(self.id, recipient_id)
        self.sign(doc)
        payload = json.dumps({'doc': {'content': doc.content, 'type': doc.type, 'id': doc.id, 'ts': doc.ts, 'sender': doc.sender}, 'sig': doc.signature}).encode()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        ct = cipher.encryptor().update(pkcs7_pad(payload)) + cipher.encryptor().finalize()
        return {'sender': self.id, 'recipient': recipient_id, 'iv': base64.b64encode(iv).decode(), 'ct': base64.b64encode(ct).decode()}

    def decrypt(self, package: dict) -> Optional[Document]:
        sender = package['sender']
        if not self.km.is_valid(sender):
            print("Sender keys invalid")
            return None
        key = self.km.get_session(self.id, sender)
        if not key:
            print("No session key")
            return None
        iv = base64.b64decode(package['iv'])
        ct = base64.b64decode(package['ct'])
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        plain = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        data = json.loads(pkcs7_unpad(plain).decode())
        d = Document(data['doc']['content'], data['doc']['type'], data['doc']['id'])
        d.ts = data['doc']['ts']; d.sender = data['doc']['sender']; d.signature = data['sig']
        if self.verify(d, sender):
            self.inbox.append(d)
            return d
        print("Signature invalid")
        return None

    def send(self, doc: Document, recipient: 'Subsystem'):
        pkg = self.encrypt(doc, recipient.id)
        return recipient.decrypt(pkg)


# --- Demonstration (compact) ---
def main():
    km = KeyManager()
    A = Subsystem("SYSTEM_A", "Finance", km)
    B = Subsystem("SYSTEM_B", "HR", km)
    C = Subsystem("SYSTEM_C", "SupplyChain", km)

    # A -> B
    doc1 = Document("Q4 Report", "Financial", "FIN-001")
    r1 = A.send(doc1, B)
    print("A->B delivered:", bool(r1))

    # B -> A
    doc2 = Document("Employee Contract", "HR", "HR-001")
    r2 = B.send(doc2, A)
    print("B->A delivered:", bool(r2))

    # Add D and send
    D = Subsystem("SYSTEM_D", "IT", km)
    doc3 = Document("Policy", "IT", "IT-001")
    print("D->A delivered:", bool(D.send(doc3, A)))

    # Revoke D and attempt send
    km.revoke("SYSTEM_D")
    try:
        pkg = D.encrypt(Document("Should Fail", "Test", "T-001"), "SYSTEM_A")
        out = A.decrypt(pkg)
        print("After revoke delivered:", bool(out))
    except Exception as e:
        print("After revoke error (expected):", e)

    # Summary counts
    print("A inbox:", len(A.inbox), "B inbox:", len(B.inbox), "C inbox:", len(C.inbox), "D inbox:", len(D.inbox))


if __name__ == "__main__":
    main()