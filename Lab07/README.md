# Lab 7: Partial Homomorphic Encryption 

## Objectives   
• Implement and Understand Additive Homomorphic Encryption   
• Implement and Understand Multiplicative Homomorphic Encryption   
•  Evaluate and Apply Partial Homomorphic Encryption   

## Lab Exercises
1. Implement the Paillier encryption scheme in Python. Encrypt two integers (e.g., 15 and 25) 
using your implementation of the Paillier encryption scheme. Print the ciphertexts. Perform 
an addition operation on the encrypted integers without decrypting them. Print the result of 
the addition in encrypted form. Decrypt the result of the addition and verify that it matches 
the sum of the original integers.   
2. Utilize the multiplicative homomorphic property of RSA encryption. Implement a basic 
RSA encryption scheme in Python. Encrypt two integers (e.g., 7 and 3) using your 
implementation of the RSA encryption scheme. Print the ciphertexts. Perform a 
multiplication operation on the encrypted integers without decrypting them. Print the result 
of the multiplication in encrypted form. Decrypt the result of the multiplication and verify 
that it matches the product of the original integers.

## Additional Exercises  

1. Implement similar exercise for other PHE operations (like homomorphic multiplication using ElGamal) 
or explore different functionalities within Paillier.   
1a: Homomorphic Multiplication (ElGamal Cryptosystem): Implement ElGamal encryption 
and demonstrate homomorphic multiplication on encrypted messages. (ElGamal supports 
multiplication but not homomorphic addition.)   
1b: Secure Data Sharing (Paillier): Simulate a scenario where two parties share encrypted data 
and perform calculations on the combined data without decryption.   
1c: Secure Thresholding (PHE): Explore how PHE can be used for secure multi-party 
computation, where a certain number of parties need to collaborate on a computation without 
revealing their individual data.   
1d: Performance Analysis (Benchmarking): Compare the performance of different PHE 
schemes (Paillier and ElGamal) for various operations.   
