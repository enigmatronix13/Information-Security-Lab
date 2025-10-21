'''
1. Implement the hash function in Python. Your function should start with 
an initial hash value of 5381 and for each character in the input string, 
multiply the current hash value by 33, add the ASCII value of the 
character, and use bitwise operations to ensure thorough mixing of the 
bits. Finally, ensure the hash value is kept within a 32-bit range by 
applying an appropriate mask.
'''

def custom_hash(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = ((hash_value * 33) + ord(char)) & 0xFFFFFFFF  # Multiply by 33, add char ASCII, keep 32-bit mask
        # Optionally, use some bitwise operations for mixing bits
        hash_value = (hash_value ^ (hash_value >> 16)) & 0xFFFFFFFF
    return hash_value

# Example usage:
input_str = "example"
print(f"Hash of '{input_str}': {custom_hash(input_str)}")