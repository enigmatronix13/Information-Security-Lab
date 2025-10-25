'''
Using socket programming in Python, demonstrate the application of 
hash functions for ensuring data integrity during transmission over a 
network. Write server and client scripts where the server computes the 
hash of received data and sends it back to the client, which then verifies 
the integrity of the data by comparing the received hash with the locally 
computed hash. Show how the hash verification detects data corruption 
or tampering during transmission.
'''

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