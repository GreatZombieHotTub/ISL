import time

# ============================================================
# PUBLIC PARAMETERS
# ============================================================

p = 23
g = 5


# ============================================================
# KEY GENERATION
# ============================================================

start = time.perf_counter()

# Alice's private key
alice_private = 6

# Bob's private key
bob_private = 15

# Alice's public key
alice_public = pow(g, alice_private, p)

# Bob's public key
bob_public = pow(g, bob_private, p)

key_generation_time = time.perf_counter() - start


# ============================================================
# KEY EXCHANGE
# ============================================================

start = time.perf_counter()

# Alice calculates shared secret
alice_shared_secret = pow(
    bob_public,
    alice_private,
    p
)

# Bob calculates shared secret
bob_shared_secret = pow(
    alice_public,
    bob_private,
    p
)

key_exchange_time = time.perf_counter() - start


# ============================================================
# OUTPUT
# ============================================================

print("PUBLIC PARAMETERS")
print("-------------------------")
print("p =", p)
print("g =", g)

print("\nALICE")
print("-------------------------")
print("Private Key:", alice_private)
print("Public Key :", alice_public)

print("\nBOB")
print("-------------------------")
print("Private Key:", bob_private)
print("Public Key :", bob_public)

print("\nSHARED SECRET")
print("-------------------------")
print("Alice:", alice_shared_secret)
print("Bob  :", bob_shared_secret)

print("\nPERFORMANCE")
print("-------------------------")
print(
    f"Key Generation Time: "
    f"{key_generation_time:.6f} seconds"
)

print(
    f"Key Exchange Time: "
    f"{key_exchange_time:.6f} seconds"
)

if alice_shared_secret == bob_shared_secret:
    print("\nSUCCESS: Both parties have the same shared secret.")
else:
    print("\nFAILED: Shared secrets do not match.")