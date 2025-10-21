# Lab 1: Basic Symmetric Key Ciphers  

## Objectives 
• To familiarize with Substitution Ciphers.   
• To understand the working of transposition ciphers.    

## Lab Exercises  
1. Encrypt the message "I am learning information security" using one of the following ciphers.  
   Ignore the space between words. Decrypt the message to get the original plaintext:  
   a) Additive cipher with key = 20  
   b) Multiplicative cipher with key = 15  
   c) Affine cipher with key = (15, 20)  

2. Encrypt the message "the house is being sold tonight" using one of the following ciphers.  
   Ignore the space between words. Decrypt the message to get the original plaintext:  
   • Vigenere cipher with key: "dollars"  
   • Autokey cipher with key = 7  

3. Use the Playfair cipher to encipher the message "The key is hidden under the door pad".  
   The secret key can be made by filling the first and part of the second row with the word "GUIDANCE" and filling the rest of the matrix with the rest of the alphabet.  

4. Use a Hill cipher to encipher the message "We live in an insecure world". Use the following key:
   ```
   K = [03 03 02 07]  
   ```
6. John is reading a mystery book involving cryptography. In one part of the book, the author gives a ciphertext "CIW" and two paragraphs later the author tells the reader that this is a shift cipher and the plaintext is "yes". In the next chapter, the hero found a tablet in a cave with "XVIEWYWI" engraved on it. John immediately found the actual meaning of the ciphertext.  
   Identify the type of attack and plaintext.  

7. Use a brute-force attack to decipher the following message. Assume that you know it is an affine cipher and that the plaintext "ab" is enciphered to "GL":  
   ```
    XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS
   ```
