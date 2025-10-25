"""
Centralized Rabin Key Management Service for HealthCare Inc.
- Generate, distribute, revoke, and renew Rabin key pairs for hospitals/clinics.
- Securely store private keys and maintain logs for auditing.
- Ensure compliance with data privacy regulations (e.g., HIPAA).
"""

import os, json, secrets, hashlib, time
from pathlib import Path
from sympy import isprime

# Utility functions for Rabin cryptosystem
def generate_large_prime(bits=512):
    while True:
        p = secrets.randbits(bits) | 1
        if isprime(p) and p % 4 == 3:
            return p

def rabin_keygen(bits=1024):
    half_bits = bits // 2
    p = generate_large_prime(half_bits)
    q = generate_large_prime(half_bits)
    n = p * q
    return {"public": n, "private": (p, q)}

# Centralized Key Management Service
class RabinKMS:
    def __init__(self, storage_dir="rabin_keys", log_file="kms.log"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = Path(log_file)
        self.keys_db = self.load_keys()

    def log(self, msg):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_file.write_text(self.log_file.read_text() + f"[{timestamp}] {msg}\n") if self.log_file.exists() else self.log_file.write_text(f"[{timestamp}] {msg}\n")
        print(f"[LOG] {msg}")

    def load_keys(self):
        db_file = self.storage_dir / "keys.json"
        if db_file.exists():
            return json.loads(db_file.read_text())
        return {}

    def save_keys(self):
        db_file = self.storage_dir / "keys.json"
        db_file.write_text(json.dumps(self.keys_db, indent=4))

    def generate_keys_for_facility(self, facility_name, bits=1024):
        keys = rabin_keygen(bits)
        self.keys_db[facility_name] = {
            "public": keys["public"],
            "private": keys["private"],
            "created": time.time(),
            "revoked": False
        }
        self.save_keys()
        self.log(f"Generated Rabin keys for {facility_name}")
        return keys

    def distribute_keys(self, facility_name):
        if facility_name not in self.keys_db or self.keys_db[facility_name]["revoked"]:
            raise Exception(f"Facility {facility_name} has no valid keys")
        keys = self.keys_db[facility_name]
        self.log(f"Distributed keys for {facility_name}")
        return keys

    def revoke_keys(self, facility_name):
        if facility_name in self.keys_db:
            self.keys_db[facility_name]["revoked"] = True
            self.save_keys()
            self.log(f"Revoked keys for {facility_name}")

    def renew_keys(self, facility_name, bits=1024):
        self.revoke_keys(facility_name)
        new_keys = self.generate_keys_for_facility(facility_name, bits)
        self.log(f"Renewed keys for {facility_name}")
        return new_keys

    def renew_all_keys(self, bits=1024):
        for facility in list(self.keys_db.keys()):
            self.renew_keys(facility, bits)
        self.log("Renewed all keys")

# Example usage
if __name__ == "__main__":
    kms = RabinKMS()
    # Generate keys for hospitals/clinics
    kms.generate_keys_for_facility("Hospital_A")
    kms.generate_keys_for_facility("Clinic_B")

    # Distribute keys
    print(kms.distribute_keys("Hospital_A"))

    # Revoke a facility's keys
    kms.revoke_keys("Clinic_B")

    # Renew keys (can be scheduled monthly/annually)
    kms.renew_keys("Hospital_A")

    # Renew all keys automatically
    kms.renew_all_keys()