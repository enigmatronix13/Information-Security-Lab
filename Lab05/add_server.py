'''
Write server and client scripts where the client sends a message in multiple parts to
the server, the server reassembles the message, computes the hash of the reassembled
message, and sends this hash back to the client. The client then verifies the integrity
of the message by comparing the received hash with the locally computed hash of the
original message. 
'''

import socket
import hashlib

def compute_hash(message):
    """Compute SHA-256 hash of the given message."""
    return hashlib.sha256(message.encode()).hexdigest()

def start_server(host='localhost', port=5000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"[SERVER] Listening on {host}:{port}...")

    conn, addr = server_socket.accept()
    print(f"[SERVER] Connection established with {addr}")

    full_message = ""
    while True:
        data = conn.recv(1024).decode()
        if data == "END":
            break
        full_message += data
        print(f"[SERVER] Received part: {data}")

    print(f"[SERVER] Full message reassembled: {full_message}")

    # Compute hash of the reassembled message
    message_hash = compute_hash(full_message)
    print(f"[SERVER] Computed SHA-256 hash: {message_hash}")

    # Send hash back to client
    conn.send(message_hash.encode())
    print("[SERVER] Hash sent to client.")

    conn.close()
    server_socket.close()
    print("[SERVER] Connection closed.")

if __name__ == "__main__":
    start_server()
