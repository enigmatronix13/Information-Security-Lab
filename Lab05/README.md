# Lab 5 : Hashing

## Objectives
1. To implement user defined hashing function. 
2. To demonstrate the application of hash function.

## Lab Exercises 
1. Implement the hash function in Python. Your function should start with 
an initial hash value of 5381 and for each character in the input string, 
multiply the current hash value by 33, add the ASCII value of the 
character, and use bitwise operations to ensure thorough mixing of the 
bits. Finally, ensure the hash value is kept within a 32-bit range by 
applying an appropriate mask.

2. Using socket programming in Python, demonstrate the application of 
hash functions for ensuring data integrity during transmission over a 
network. Write server and client scripts where the server computes the 
hash of received data and sends it back to the client, which then verifies 
the integrity of the data by comparing the received hash with the locally 
computed hash. Show how the hash verification detects data corruption 
or tampering during transmission.

3. Design a Python-based experiment to analyze the performance of MD5, 
SHA-1, and SHA-256 hashing techniques in terms of computation time 
and collision resistance. Generate a dataset of random strings ranging 
from 50 to 100 strings, compute the hash values using each hashing 
technique, and measure the time taken for hash computation. Implement 
collision detection algorithms to identify any collisions within the 
hashed dataset.

## Additional Exercise 

1. Write server and client scripts where the client sends a message in multiple parts to 
the server, the server reassembles the message, computes the hash of the reassembled 
message, and sends this hash back to the client. The client then verifies the integrity 
of the message by comparing the received hash with the locally computed hash of the 
original message. 
