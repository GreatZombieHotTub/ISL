#Implement Diffie–Hellman and verify that both parties generate the same shared secret.
import secrets

# Public parameters
p = 23
g = 5

# Private keys
alice_private = secrets.randbelow(p - 2) + 1
bob_private = secrets.randbelow(p - 2) + 1

# Public keys
alice_public = pow(g, alice_private, p)
bob_public = pow(g, bob_private, p)

# Shared secrets
alice_shared = pow(
    bob_public,
    alice_private,
    p
)

bob_shared = pow(
    alice_public,
    bob_private,
    p
)

print("Alice Public Key :", alice_public)
print("Bob Public Key   :", bob_public)
print("Alice Shared Key :", alice_shared)
print("Bob Shared Key   :", bob_shared)
print("Keys Match       :", alice_shared == bob_shared)