# Lab 8: Searchable Encryption   

## Objectives 
- Understand the Fundamentals of Searchable Encryption (SE) 
- Implement and Perform Encrypted Data Searches 
- Analyze the Security and Efficiency Trade-offs

## Lab Exercises

1. Execute the following for SSE:   
1a. Create a dataset: Generate a text corpus of at least ten documents. Each document 
should contain multiple words.   
1b. Implement encryption and decryption functions: Use the AES encryption and 
decryption functions.   
1c. Create an inverted index: Build an inverted index mapping word to the list of 
document IDs containing those words.   
o Encrypt the index using the provided encryption function.   
1d. Implement the search function:   
o Take a search query as input.   
o Encrypt the query.   
o Search the encrypted index for matching terms.   
o Decrypt the returned document IDs and display the corresponding documents

2. Execute the following for PKSE:   
2a. Create a dataset:   
o Generate a text corpus of at least ten documents. Each document should contain 
multiple words.   
2b. Implement encryption and decryption functions:   
o Use the Paillier cryptosystem for encryption and decryption.   
2c. Create an encrypted index:   
o Build an inverted index mapping word to the list of document IDs containing 
those words.   
o Encrypt the index using the Paillier cryptosystem.   
2d. Implement the search function:   
o Take a search query as input.   
o Encrypt the query using the public key.   
o Search the encrypted index for matching terms.   
o Decrypt the returned document IDs using the private key.   

## Additional Questions   
1. Demonstrate how to securely store and transmit data using GnuPG. Additionally, show 
how to create a digital signature for the data and verify the signature after transmission.   
2. Configure and use Snort as a Network Intrusion Detection System (NIDS) to monitor real
time network traffic. Capture network traffic, apply Snort rules, and analyze the logs to 
identify any potential intrusions.   