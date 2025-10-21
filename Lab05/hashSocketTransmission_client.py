import socket
import hashlib

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()
# Client code
def client_program(message, corrupt=False, host='127.0.0.1', port=65432):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    if corrupt:
        message = b"corrupted_data"  # Simulate corruption
    
    print(f"Client sending message: {message}")
    client_socket.sendall(message)

    received_hash = client_socket.recv(1024).decode()
    print(f"Client received hash from server: {received_hash}")

    local_hash = compute_hash(message)
    print(f"Client locally computed hash: {local_hash}")

    if received_hash == local_hash:
        print("Data integrity verified: hashes match.")
    else:
        print("Data integrity compromised: hashes do not match!")

    client_socket.close()