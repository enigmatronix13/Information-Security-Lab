'''
Design a Python-based experiment to analyze the performance of MD5, 
SHA-1, and SHA-256 hashing techniques in terms of computation time 
and collision resistance. Generate a dataset of random strings ranging 
from 50 to 100 strings, compute the hash values using each hashing 
technique, and measure the time taken for hash computation. Implement 
collision detection algorithms to identify any collisions within the 
hashed dataset.   
'''
import hashlib
import random
import string
import time

# Generate random dataset of strings
def generate_random_strings(n, length=10):
    dataset = []
    for _ in range(n):
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        dataset.append(s)
    return dataset

# Hashing functions
hash_functions = {
    'MD5': hashlib.md5,
    'SHA1': hashlib.sha1,
    'SHA256': hashlib.sha256
}

# Experiment: compute hashes and measure time
def experiment(dataset):
    results = {}
    for name, func in hash_functions.items():
        start = time.time()
        hashes = []
        collisions = {}
        for item in dataset:
            h = func(item.encode()).hexdigest()
            hashes.append(h)
            if h in collisions:
                collisions[h].append(item)
            else:
                collisions[h] = [item]
        end = time.time()
        
        # Count collisions (where >1 string maps to same hash)
        collision_count = sum(1 for v in collisions.values() if len(v) > 1)
        
        results[name] = {
            'time_taken': end - start,
            'collision_count': collision_count,
            'unique_hashes': len(set(hashes)),
            'total_hashes': len(hashes)
        }
    return results

if __name__ == "__main__":
    # Generate dataset of 50–100 random strings
    n = random.randint(50, 100)
    dataset = generate_random_strings(n)
    print(f"Generated dataset size: {n}")
    
    # Run experiment
    results = experiment(dataset)
    
    # Display results
    for algo, stats in results.items():
        print(f"\nAlgorithm: {algo}")
        print(f"Time taken: {stats['time_taken']:.6f} seconds")
        print(f"Collisions found: {stats['collision_count']}")
        print(f"Unique hashes: {stats['unique_hashes']} / {stats['total_hashes']}")
    print("\nExperiment completed.")