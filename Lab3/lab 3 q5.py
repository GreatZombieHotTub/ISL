import random
import time

p = 23
g = 5

# Alice
start = time.perf_counter()
alice_private = random.randint(2, p - 2)
alice_private_time = time.perf_counter() - start

start = time.perf_counter()
alice_public = pow(g, alice_private, p)
alice_public_time = time.perf_counter() - start

# Bob
start = time.perf_counter()
bob_private = random.randint(2, p - 2)
bob_private_time = time.perf_counter() - start

start = time.perf_counter()
bob_public = pow(g, bob_private, p)
bob_public_time = time.perf_counter() - start

# Shared secret
start = time.perf_counter()
alice_shared_secret = pow(bob_public, alice_private, p)
alice_secret_time = time.perf_counter() - start

start = time.perf_counter()
bob_shared_secret = pow(alice_public, bob_private, p)
bob_secret_time = time.perf_counter() - start


print("Public Parameters:")
print("p =", p)
print("g =", g)

print("\nAlice:")
print("Private Key:", alice_private)
print("Public Key:", alice_public)
print("Private Key Generation Time:", alice_private_time)
print("Public Key Generation Time:", alice_public_time)
print("Shared Secret:", alice_shared_secret)
print("Shared Secret Generation Time:", alice_secret_time)

print("\nBob:")
print("Private Key:", bob_private)
print("Public Key:", bob_public)
print("Private Key Generation Time:", bob_private_time)
print("Public Key Generation Time:", bob_public_time)
print("Shared Secret:", bob_shared_secret)
print("Shared Secret Generation Time:", bob_secret_time)

print("\nSame Shared Secret:",
      alice_shared_secret == bob_shared_secret)