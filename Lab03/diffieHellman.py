import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

def generate_dh_parameters():
    # Use a safe prime group, 2048-bit
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_dh_keypair(parameters):
    start = time.time()
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    end = time.time()
    return private_key, public_key, end - start

def compute_shared_secret(private_key, peer_public_key):
    start = time.time()
    shared_key = private_key.exchange(peer_public_key)
    end = time.time()
    return shared_key, end - start

if __name__ == "__main__":
    print("Generating DH parameters...")
    params = generate_dh_parameters()

    # Peer A key generation
    priv_a, pub_a, time_keygen_a = generate_dh_keypair(params)
    print(f"Peer A key generation time: {time_keygen_a:.6f} seconds")

    # Peer B key generation
    priv_b, pub_b, time_keygen_b = generate_dh_keypair(params)
    print(f"Peer B key generation time: {time_keygen_b:.6f} seconds")

    # Simulate exchange of public keys over insecure channel
    # Now both peers compute the shared secret

    shared_secret_a, time_shared_a = compute_shared_secret(priv_a, pub_b)
    shared_secret_b, time_shared_b = compute_shared_secret(priv_b, pub_a)

    print(f"Peer A computes shared secret in: {time_shared_a:.6f} seconds")
    print(f"Peer B computes shared secret in: {time_shared_b:.6f} seconds")

    # Check that both shared secrets match
    if shared_secret_a == shared_secret_b:
        print("Success: Both peers computed the same shared secret.")
    else:
        print("Error: Shared secrets do NOT match!")