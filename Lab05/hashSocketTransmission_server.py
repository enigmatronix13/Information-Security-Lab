import socket
import hashlib

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

# Server code
def server_program(host='127.0.0.1', port=65432):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server listening on {host}:{port}...\n")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        data = conn.recv(1024)
        if not data:
            conn.close()
            continue
        print(f"Server received data: {data}")

        hash_value = compute_hash(data)
        print(f"Server computed hash: {hash_value}")

        conn.sendall(hash_value.encode())
        conn.close()