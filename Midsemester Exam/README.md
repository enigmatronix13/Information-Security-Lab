## Question

### On the Client Side
Take an input message M and perform the following sequence of operations:
1. Encrypt the message M using the RSA algorithm and send the ciphertext to the server.
2. Compute the SHA-256 hash of M, then apply a Row Transposition Cipher followed by a Columnar Transposition Cipher on the hash value, and send the resulting ciphertext to the server.
3. Generate a digital signature using the ElGamal Digital Signature Scheme and send it along.

### On the Server Side
1. Verify the ElGamal digital signature.
2. If the signature is valid, decrypt the received RSA ciphertext to recover the original message.
