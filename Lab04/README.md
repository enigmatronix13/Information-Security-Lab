# Lab 4: Advanced Asymmetric Key Ciphers 

## Objectives  
• Implement and compare the performance of multiple asymmetric encryption algorithms (e.g., 
RSA, ElGamal, Rabin) in a controlled environment, measuring factors such as 
encryption/decryption speed and key generation time.   
• Design and develop a modular key management system capable of handling various 
cryptographic protocols, with emphasis on scalability, security, and ease of integration.   
• Create a flexible framework for testing different access control mechanisms in cryptographic 
systems, allowing for easy implementation and evaluation of various policies and revocation 
strategies.  

## Lab Exercises

### Question 1:  
SecureCorp is a large enterprise with multiple subsidiaries and business units located across 
different geographical regions. As part of their digital transformation initiative, the IT team at 
SecureCorp has been tasked with building a secure and scalable communication system to 
enable seamless collaboration and information sharing between their various subsystems. 
The enterprise system consists of the following key subsystems:   
1. Finance System (System A): Responsible for all financial record-keeping, accounting, and  reporting.   
2. HR System (System B): Manages employee data, payroll, and personnel-related processes.   
3. Supply Chain Management (System C): Coordinates the flow of goods, services, and 
information across the organization's supply chain.   
These subsystems need to communicate securely and exchange critical documents, such as 
financial reports, employee contracts, and procurement orders, to ensure the enterprise's 
overall efficiency. 
The IT team at SecureCorp has identified the following requirements for the secure 
communication and document signing solution:   
1. Secure Communication: The subsystems must be able to establish secure communication 
channels using a combination of RSA encryption and Diffie-Hellman key exchange.   
2. Key Management: SecureCorp requires a robust key management system to generate, 
distribute, and revoke keys as needed to maintain the security of the enterprise system.   
3. Scalability: The solution must be designed to accommodate the addition of new subsystems 
in the future as SecureCorp continues to grow and expand its operations.   
Implement a Python program which incorporates the requirements.

### Question 2:   
HealthCare Inc., a leading healthcare provider, has implemented a secure patient data 
management system using the Rabin cryptosystem. The system allows authorized healthcare  
professionals to securely access and manage patient records across multiple hospitals and 
clinics within the organization. Implement a Python-based centralized key management 
service that can:   
• Key Generation: Generate public and private key pairs for each hospital and clinic using 
the Rabin cryptosystem. The key size should be configurable (e.g., 1024 bits).   
• Key Distribution: Provide a secure API for hospitals and clinics to request and receive 
their public and private key pairs.   
• Key Revocation: Implement a process to revoke and update the keys of a hospital or 
clinic when necessary (e.g., when a facility is closed or compromised).   
• Key Renewal: Automatically renew the keys of all hospitals and clinics at regular 
intervals (e.g., every 12 months) to maintain the security of the patient data management 
system.   
• Secure Storage: Securely store the private keys of all hospitals and clinics, ensuring that 
they are not accessible to unauthorized parties.   
• Auditing and Logging: Maintain detailed logs of all key management operations, such 
as key generation, distribution, revocation, and renewal, to enable auditing and 
compliance reporting.   
• Regulatory Compliance: Ensure that the key management service and its operations are 
compliant with relevant data privacy regulations (e.g., HIPAA).   
• Perform a trade-off analysis to compare the workings of Rabin and RSA.   

## Additional Questions   

### Question 1:     
DigiRights Inc. is a leading provider of digital content, including e-books, movies, and music. 
The company has implemented a secure digital rights management (DRM) system using the 
ElGamal cryptosystem to protect its valuable digital assets. Implement a Python-based 
centralized key management and access control service that can:   
• Key Generation: Generate a master public-private key pair using the ElGamal 
cryptosystem. The key size should be configurable (e.g., 2048 bits).   
• Content Encryption: Provide an API for content creators to upload their digital content and 
have it encrypted using the master public key.   
• Key Distribution: Manage the distribution of the master private key to authorized 
customers, allowing them to decrypt the content.   
• Access Control: Implement flexible access control mechanisms, such as:   
o Granting limited-time access to customers for specific content   
o Revoking access to customers for specific content   
o Allowing content creators to manage access to their own content   
• Key Revocation: Implement a process to revoke the master private key in case of a security 
breach or other emergency.     
• Key Renewal: Automatically renew the master public-private key pair at regular intervals 
(e.g., every 24 months) to maintain the security of the DRM system. 
• Secure Storage: Securely store the master private key, ensuring that it is not accessible to 
unauthorized parties.   
• Auditing and Logging: Maintain detailed logs of all key management and access control 
operations to enable auditing and troubleshooting.     

### Question 2:    
Suppose that XYZ Logistics has decided to use the RSA cryptosystem to secure their sensitive 
communications. However, the security team at XYZ Logistics has discovered that one of their 
employees, Eve, has obtained a partial copy of the RSA private key and is attempting to 
recover the full private key to decrypt the company's communications.   
Eve's attack involves exploiting a vulnerability in the RSA key generation process, where the 
prime factors (p and q) used to generate the modulus (n) are not sufficiently large or random. 
Develop a Python script that can demonstrate the attack on the vulnerable RSA cryptosystem  
and discuss the steps to mitigate the attack.  
