import hashlib
import random
import string
import time


def generate_string(length=20):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


data = []

#data holds 100 strings
for i in range(100):
    data.append(generate_string())


algorithms = ["MD5", "SHA-1", "SHA-256"]


for algorithm in algorithms:

    start_time = time.perf_counter()

    hashes = []

    for message in data:

        if algorithm == "MD5":
            hash_value = hashlib.md5(message.encode()).hexdigest()

        elif algorithm == "SHA-1":
            hash_value = hashlib.sha1(message.encode()).hexdigest()

        else:
            hash_value = hashlib.sha256(message.encode()).hexdigest()

        hashes.append(hash_value)

    end_time = time.perf_counter()

    computation_time = end_time - start_time

    #collisions is when 2 different data give same value after being put thru hash func

    collisions = len(hashes) - len(set(hashes))

    print("\nAlgorithm:", algorithm)
    print("Computation time:", computation_time, "seconds")
    print("Collisions:", collisions)