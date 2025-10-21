# Lab 3: Asymmetric Key Ciphers

## Objectives 
• To demonstrate the ability to generate, use, and understand the public and private keys in 
various asymmetric encryption schemes.   
• To understand the performance implications of different asymmetric encryption algorithms 
Asymmetric algorithms rely on one key for encryption and a different but related key for 
decryption. These algorithms have the following important characteristics: 
  1. It is computationally infeasible to determine the decryption key given only knowledge of 
cryptographic algorithms and encryption keys.
  2. Either of the two related keys can be used for encryption, with the other used for decryption.
     
## Lab Exercises  
1. Using RSA, encrypt the message "Asymmetric Encryption" with the public key (n, e). Then 
decrypt the ciphertext with the private key (n, d) to verify the original message.   
2. Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure Transactions" with 
the public key. Then decrypt the ciphertext with the private key to verify the original message.   
3. Given an ElGamal encryption scheme with a public key (p, g, h) and a private key x, encrypt 
the message "Confidential Data". Then decrypt the ciphertext to retrieve the original message.     
4. Design and implement a secure file transfer system using RSA (2048-bit) and ECC (secp256r1 
curve) public key algorithms. Generate and exchange keys, then encrypt and decrypt files of 
varying sizes (e.g., 1 MB, 10 MB) using both algorithms. Measure and compare the 
performance in terms of key generation time, encryption/decryption speed, and computational 
overhead. Evaluate the security and efficiency of each algorithm in the context of file transfer, 
considering factors such as key size, storage requirements, and resistance to known attacks. 
Document your findings, including performance metrics and a summary of the strengths and 
weaknesses of RSA and ECC for secure file transfer.   
5. As part of a project to enhance the security of communication in a peer-to-peer file sharing 
system, you are tasked with implementing a secure key exchange mechanism using the Diffie
Hellman algorithm. Each peer must establish a shared secret key with another peer over an 
insecure channel. Implement the Diffie-Hellman key exchange protocol, enabling peers to

## Additional Exercises

Additional Exercises: 
1. With the ElGamal public key (p = 7919, g = 2, h = 6465) and the private key x = 2999, encrypt 
the message "Asymmetric Algorithms". Decrypt the resulting ciphertext to verify the original 
message. 
2. Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure Transactions" with 
the public key. Then decrypt the ciphertext with the private key to verify the original message. 
3. Encrypt the message "Cryptographic Protocols" using the RSA public key (n, e) where n = 
323 and e = 5. Decrypt the ciphertext with the private key (n, d) where d = 173 to confirm the 
original message 
4. You are tasked with implementing a secure communication system for a healthcare 
organization to exchange sensitive patient information securely between doctors and hospitals. 
Implement the ElGamal encryption scheme to encrypt patient records and medical data, 
ensuring confidentiality during transmission. Generate public and private keys using the 
secp256r1 curve and use ElGamal encryption to encrypt patient data with the recipient's public 
key and decrypt it with the recipient's private key. Measure the performance of encryption and 
decryption processes for data of varying sizes. 
5. You are conducting a study to evaluate the performance and security of RSA and ElGamal 
encryption algorithms in securing communication for a government agency. Implement both 
RSA (using 2048-bit keys) and ElGamal (using the secp256r1 curve) encryption schemes to 
encrypt and decrypt sensitive messages exchanged between agencies. Measure the time taken 
for key generation, encryption, and decryption processes for messages of various sizes (e.g., 1 
KB, 10 KB). Compare the computational efficiency and overhead of RSA and ElGamal 
algorithms. Perform the same for ECC with RSA and ElGamal.
generate their public and private keys and securely compute the shared secret key. Measure 
the time taken for key generation and key exchange processes.
