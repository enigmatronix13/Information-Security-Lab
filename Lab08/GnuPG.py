'''
Demonstrate how to securely store and transmit data using GnuPG. Additionally, show how to create a digital signature for the data and verify the signature after transmission.  
'''

import gnupg, os, tempfile, shutil
from pathlib import Path

class SecureDataHandler:
    def __init__(self, gpg_home=None):
        if gpg_home:
            os.environ["GNUPGHOME"] = gpg_home
        self.gpg = gnupg.GPG()

    def generate_key(self, name, email, passphrase, key_type='RSA', key_length=2048):
        key = self.gpg.gen_key(self.gpg.gen_key_input(
            name_real=name, name_email=email, passphrase=passphrase,
            key_type=key_type, key_length=key_length))
        return str(key)

    def list_keys(self, secret=False):
        return self.gpg.list_keys(secret)

    def export_public_key(self, key_id, output_file=None):
        key = self.gpg.export_keys(key_id)
        if output_file:
            Path(output_file).write_text(key)
        return key

    def import_key(self, key_data=None, key_file=None):
        if key_file:
            key_data = Path(key_file).read_text()
        return self.gpg.import_keys(key_data)

    def encrypt_data(self, data, recipient, output_file=None, sign=False, passphrase=None):
        enc = self.gpg.encrypt(data, recipient, sign=sign, passphrase=passphrase, always_trust=True)
        if not enc.ok: raise Exception(enc.status)
        if output_file: Path(output_file).write_text(str(enc))
        return str(enc)

    def decrypt_data(self, encrypted_data, passphrase, input_file=None):
        if input_file:
            encrypted_data = Path(input_file).read_text()
        dec = self.gpg.decrypt(encrypted_data, passphrase=passphrase)
        if not dec.ok: raise Exception(dec.status)
        return str(dec)

    def sign_data(self, data, keyid=None, passphrase=None, detach=True, output_file=None):
        sig = self.gpg.sign(data, keyid=keyid, passphrase=passphrase, detach=detach)
        if not sig.data: raise Exception(sig.status)
        if output_file: Path(output_file).write_text(str(sig))
        return str(sig)

    def verify_signature(self, data, signature=None, signature_file=None):
        if signature_file:
            signature = Path(signature_file).read_text()
        v = self.gpg.verify_data(signature, data.encode() if isinstance(data, str) else data) if signature else self.gpg.verify(data)
        return {'valid': v.valid, 'fingerprint': v.fingerprint, 'username': v.username,
                'key_id': v.key_id, 'signature_id': v.signature_id, 'trust_level': v.trust_text}

    def encrypt_and_sign(self, data, recipient, passphrase, output_file=None):
        enc = self.gpg.encrypt(data, recipient, sign=True, passphrase=passphrase, always_trust=True)
        if not enc.ok: raise Exception(enc.status)
        if output_file: Path(output_file).write_text(str(enc))
        return str(enc)


def main():
    print("="*60, "\nGnuPG Secure Data Storage and Transmission Demo\n", "="*60)
    temp_dir = tempfile.mkdtemp()
    print(f"\nUsing temporary GPG home: {temp_dir}\n")
    handler = SecureDataHandler(gpg_home=temp_dir)

    alice_pass, bob_pass = "alice_secure_password", "bob_secure_password"
    alice_key = handler.generate_key("Alice Smith", "alice@example.com", alice_pass)
    bob_key = handler.generate_key("Bob Jones", "bob@example.com", bob_pass)

    keys = handler.list_keys()
    for key in keys:
        if 'alice@example.com' in key['uids'][0]: alice_fp = key['fingerprint']
        elif 'bob@example.com' in key['uids'][0]: bob_fp = key['fingerprint']

    handler.export_public_key(alice_fp, 'alice_public.asc')
    handler.export_public_key(bob_fp, 'bob_public.asc')

    msg = "Hello Bob! This is a confidential message from Alice. 🔒"
    enc_msg = handler.encrypt_data(msg, bob_fp, 'encrypted_message.asc')
    sig = handler.sign_data(msg, keyid=alice_fp, passphrase=alice_pass, output_file='message_signature.asc')
    dec_msg = handler.decrypt_data(enc_msg, bob_pass)
    ver = handler.verify_signature(msg, signature=sig)

    print(f"\nDecrypted message: {dec_msg}")
    print(f"Verification valid: {ver['valid']} | Signer: {ver['username']}\n")

    enc_signed = handler.encrypt_and_sign("This message is both encrypted and signed!", bob_fp, alice_pass, 'encrypted_signed.asc')
    print("Encrypted + Signed message created.\n")
    print("Decrypted:", handler.decrypt_data(enc_signed, bob_pass))

    tampered = "This message has been tampered with!"
    ver_t = handler.verify_signature(tampered, signature=sig)
    print(f"Tampered verification valid: {ver_t['valid']}\n")

    for f in ['alice_public.asc', 'bob_public.asc', 'encrypted_message.asc', 'message_signature.asc', 'encrypted_signed.asc']:
        if os.path.exists(f): os.remove(f)
    shutil.rmtree(temp_dir)
    print("="*60, "\nDemo completed successfully!\n", "="*60)

if __name__ == "__main__":
    main()
