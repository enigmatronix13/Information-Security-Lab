'''
Write server and client scripts where the client sends a message in multiple parts to
the server, the server reassembles the message, computes the hash of the reassembled
message, and sends this hash back to the client. The client then verifies the integrity
of the message by comparing the received hash with the locally computed hash of the
original message.
'''

import socket
import hashlib
import time

def compute_hash(message):
    """Compute SHA-256 hash of the given message."""
    return hashlib.sha256(message.encode()).hexdigest()

def start_client(host='localhost', port=5000):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"[CLIENT] Connected to {host}:{port}")

    # Split the message into multiple parts
    original_message = "This is a long message split into multiple parts."
    parts = original_message.split()

    for part in parts:
        client_socket.send(part.encode())
        print(f"[CLIENT] Sent part: {part}")
        time.sleep(0.5)  # simulate delay

    # Indicate end of transmission
    client_socket.send("END".encode())

    # Receive hash from server
    server_hash = client_socket.recv(1024).decode()
    print(f"[CLIENT] Received hash from server: {server_hash}")

    # Compute local hash
    local_hash = compute_hash(" ".join(parts))
    print(f"[CLIENT] Local hash: {local_hash}")

    # Verify integrity
    if local_hash == server_hash:
        print("[CLIENT] Message integrity verified. No tampering detected.")
    else:
        print("[CLIENT] Message integrity check failed. Data altered.")

    client_socket.close()

if __name__ == "__main__":
    start_client()
